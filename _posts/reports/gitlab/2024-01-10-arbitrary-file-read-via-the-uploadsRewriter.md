---
layout: post
title: "Replication: Gitlab Arbitrary file read via the UploadsRewriter when moving and issue"
date: 2024-01-10 10:31:06 +0800
categories: path-traversal
---

## Name

> Gitlab Arbitrary file read via the UploadsRewriter when moving and issue

## Weakness

> path-traversal

## Severity

> 高危

## Environment

```
GitLab information

Version: 12.8.7-ee
Revision: 2643fd87200
Directory: /opt/gitlab/embedded/service/gitlab-rails
```

> 原文：[https://hackerone.com/reports/827052](https://hackerone.com/reports/827052)

**Gitlab Docker**
```
docker run --detach \
  --hostname 10.206.44.20 \
  --publish 4433:443 --publish 8033:80 --publish 2233:22 \
  --name gitlab \
  --restart always \
  --shm-size 256m \
  gitlab/gitlab-ee:12.8.7-ee.0
```

**[重置root密码失败解决方法](https://docs.gitlab.com/ee/security/reset_user_password.html#use-a-rails-console)**
```
gitlab-rails console
user = User.find_by_username 'root'
new_password = "abcd1234"
user.password = new_password
user.password_confirmation = new_password
user.password_automatically_set = false
user.skip_reconfirmation!
user.save!
```

**配置debugger**

    1. 下载ruby2.6.5，编译：https://www.ruby-lang.org/en/documentation/installation/#building-from-source
    2. 拷贝编译后的include文件夹到/opt/gitlab/embedded/
    3. 添加pry-debug库到Gemfile：/opt/gitlab/embedded/service/gitlab-rails/Gemfile  gem 'pry-byebug', '~> 3.5.1'
    4. 执行bundle install，下载debug库
    5. 其他步骤见环境配置文章

**拷贝源码/opt/gitlab/embedded/service/gitlab-rails，vscode查看**

## URL

## Summary

### Methods flow

{% mermaid %}
flowchart
    classDef red color:#022e1f,fill:#f11111;
    B[ContentRewriter.execute\napp/services/issuable/clone/content_rewriter.rb]-->A[UploadsRewriter.rewrite\nlib/gitlab/gfm/uploads_rewriter.rb]:::red
    C[BaseService.execute\napp/services/issuable/clone/base_service.rb]-->B
    D[MoveService.execute\napp/services/issues/move_service.rb]-->C
    E[UpdateService.move_issue_to_new_project\napp/services/issues/update_service.rb]-->D
    F[IssuesController.move\napp/controllers/projects/issues_controller.rb]-->E
{% endmermaid %}

可以看到issues页面提供move动作如下：

[http://10.206.44.20:8033/root/bb/issues/1](http://10.206.44.20:8033/root/bb/issues/1)

![issues_move](/assets/gitlab/2/issues_move.png)

设置断点验证成功：

![issues_debug](/assets/gitlab/2/issues_debug.png)

### Data flow

{% mermaid %}
flowchart
    classDef red color:#022e1f,fill:#f11111;
    B[ContentRewriter.execute @original_entity\napp/services/issuable/clone/content_rewriter.rb]-->A[UploadsRewriter.rewrite @text \nlib/gitlab/gfm/uploads_rewriter.rb]:::red
    C[BaseService.execute @original_entity\napp/services/issuable/clone/base_service.rb]-->B
    D[MoveService.execute issue\napp/services/issues/move_service.rb]-->C
    E[UpdateService.move_issue_to_new_project issue\napp/services/issues/update_service.rb]-->D
    F[IssuesController.move issue\napp/controllers/projects/issues_controller.rb]-->E
{% endmermaid %}

### Payload

```
[xx](/uploads/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/../../../../../../../../etc/passwd)
```

### Analysis

1. 首先需要过判断，判断该文件是否存在，判断的逻辑有些复杂，其中路径穿越在判断文件之前存在，用的是CarrierWave.retrieve_from_store!方法
    *app/uploaders/object_storage.rb:44*
    ```
    def retrieve_from_store!(identifier)
        paths = upload_paths(identifier)

        unless current_upload_satisfies?(paths, model)
            # the upload we already have isn't right, find the correct one
            self.upload = model&.retrieve_upload(identifier, paths)
        end

        super
    end
    ```
    其中super调用*/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/carrierwave-1.3.1/lib/carrierwave/storage/file.rb:53*，完成相对路径到绝对路径的转换:
    ```
    def retrieve!(identifier)
        path = ::File.expand_path(uploader.store_path(identifier), uploader.root)
        CarrierWave::SanitizedFile.new(path)
    end
    ```
    见expand_path定义：
    ```
    File.expand_path(relative_path, base_directory)
    File.expand_path is a Ruby method used to convert a relative file path to an absolute file path. 
    It takes a relative path as an argument and returns the corresponding absolute path.
    ```
    类继承关系:
    ```	
    FileUploader < GitlabUploader < CarrierWave::Uploader::Base
    FileUploader.retrieve_from_store! -> CarrierWave.retrieve_from_store!
    ```
    GitlabUploader类对CarrierWave库进行封装，被用到多处文件操作中，查找漏洞需要重点关注该类。
    *lib/gitlab/gfm/uploads_rewriter.rb:51*
    ```
    def files
        referenced_files = @text.scan(@pattern).map do
            find_file(@source_project, $~[:secret], $~[:file])
        end

        referenced_files.compact.select(&:exists?)
    end
    ```
	使用referenced_files.compact.select(&:exists?)来判断文件是否存在，调用的是referenced_files中元素也就是FileUploader对象的exists方法：
    *app/uploaders/object_storage.rb:297*
    ```
    def exists?
        file.present?
    end
    ```
2. 最后是文件拷贝
    *lib/gitlab/gfm/uploads_rewriter.rb:29*
    ```
    def rewrite(target_parent)
        return @text unless needs_rewrite?

        @text.gsub(@pattern) do |markdown|
            file = find_file(@source_project, $~[:secret], $~[:file])
            break markdown unless file.try(:exists?)

            klass = target_parent.is_a?(Namespace) ? NamespaceFileUploader : FileUploader
            moved = klass.copy_to(file, target_parent)

            moved_markdown = moved.markdown_link

            # Prevents rewrite of plain links as embedded
            if was_embedded?(markdown)
            moved_markdown
            else
            moved_markdown.sub(/\A!/, "")
            end
        end
    end
    ```
    其中copy_to方法将文件拷贝到目标路径：
    *app/uploaders/file_uploader.rb:166*
    ```
    def self.copy_to(uploader, to_project)
        moved = self.new(to_project)
        moved.object_store = uploader.object_store
        moved.filename = uploader.filename
    
        moved.copy_file(uploader.file)
        moved
    end
    def copy_file(file)
        to_path = if file_storage?
                File.join(self.class.root, store_path)
                else
                store_path
                end

        self.file = file.copy_to(to_path)
        record_upload # after_store is not triggered
    end
    ```
    最终使用carrierwave库的copy_to进行拷贝：
    */opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/carrierwave-1.3.1/lib/carrierwave/sanitized_file.rb*
    *def copy_to(new_path, permissions=nil, directory_permissions=nil)*

3. 升级为RCE，参考：[https://gist.github.com/stonegao/4051110051622cc5d5cd30721b88f24e](https://gist.github.com/stonegao/4051110051622cc5d5cd30721b88f24e)

## Tips

**路径穿越漏洞**
1. 上层，需要把每个功能点都考察一遍：
	- 是否有移动行为，该移动行为是否涉及到File.join
2. 底层，定位到功能点对应的代码：
	- File.join，是否可以控制join的某些变量，导致目录穿越问题。
	- carrierwave的copy_to方法
    - ruby File.expand_path方法相对路径转绝对路径
