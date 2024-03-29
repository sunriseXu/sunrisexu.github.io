---
layout: post
title: "Reproduction: Gitlab Stored-XSS with CSP-bypass via labels' color"
date: 2023-11-15 10:31:06 +0800
categories: xss
---

## Name

> Stored-XSS with CSP-bypass via labels' color

## Weakness

> XSS

## Severity

> 高危

## Environment

> gitlab 版本：14.5.2-ee

> 原文：[https://hackerone.com/reports/1665658](https://hackerone.com/reports/1665658)

## URL

## Summary

gitlab 导入外部 github 仓库数据，并且未对数据进行过滤，导致后端渲染时 xss。伪造 github 服务器，返回 xss payload，后端渲染的时候没有对引号进行处理，导致新的标签/属性可以插入。如下，`bg_color`字段没有进行过滤。这是后端渲染的问题，xss 在后端模板被注入

```
def render_label_text(name, suffix: '', css_class: nil, bg_color: nil)
  <<~HTML.chomp.html_safe
    <span
      class="#{css_class}"
      data-container="body"
      data-html="true"
      #{"style=\"background-color: #{bg_color}\"" if bg_color}
    >#{ERB::Util.html_escape_once(name)}#{suffix}</span>
  HTML
end
```

#### Code Review

##### 基于函数流分析

1. 首先定位到漏洞代码：
   _gitlab/app/helpers/labels_helper.rb#266_
   ```
   def render_label_text(name, suffix: '', css_class: nil, bg_color: nil)
     <<~HTML.chomp.html_safe
       <span
         class="#{css_class}"
         data-container="body"
         data-html="true"
         #{"style=\"background-color: #{bg_color}\"" if bg_color}
       >#{ERB::Util.html_escape_once(name)}#{suffix}</span>
     HTML
   end
   ```
2. 然后定位到该文件中调用该函数的两个函数，分别是 link*to_label 和 render_label，他们的第一个参数 label 包含了漏洞数据：
   \_gitlab/app/helpers/labels_helper.rb#39*

   ```
   def link_to_label(label, type: :issue, tooltip: true, small: false, css_class: nil, &block)
     render_label(label, link: link, tooltip: tooltip, small: small)

   end
   def render_label(label, link: nil, tooltip: true, dataset: nil, small: false)
     html = render_colored_label(label)
   end
   ```

3. 首先分析 render_label 函数，引用该函数进行数据渲染的地方都是模板文件，一共有三处，这三处都是 shared view：

   _gitlab/app/views/shared/\_label_row.html.haml_
   _gitlab/app/views/shared/milestones/\_issuable.html.haml_
   _gitlab/app/views/shared/milestones/\_labels_tab.html.haml_

4. 先分析第一处，旁边的\_label.html.haml 引用该模板，则搜索`shared/label`关键字
   _gitlab/app/views/shared/\_label.html.haml#10_
   ```
   %li.label-list-item{ id: label_css_id, data: { id: label.id } }
       = render "shared/label_row", label: label, force_priority: force_priority
       %ul.label-actions-list
   ```
5. 找到一处引用该模板的文件，那么 projects labels 就是路由了，进去可以看到渲染结果：
   _gitlab/app/views/projects/labels/index.html.haml_

   ![labels](/assets/gitlab/1/labels.png)

   渲染的 bg_color:

   ![bg_color](/assets/gitlab/1/bg_color.png)

6. 但是新建 label 时，后端对 label 的 color 做了 valid 校验，填入非 color 会报错无法插入数据库。因此攻击者想到 bulk*insert，该方法可以绕过校验直接插入数据库。刚好 github_import 提供 label 的 bulk_insert 功能。怎么会想到该功能呢？并且刚好有 label 模型使用该方法插入数据呢？难道这就是碰运气吗？还是说对项目的全面理解。假设我们已经找到 label 存在 bulk_insert，其位置在类 LabelsImporter 中。复现完后，我想可能是攻击者首先对 api 进行检查，当看到 import 接口可以设置自定义的域名后，就开始从头分析，而非逆向分析。因为这种导入接口大概率存在漏洞。正向分析的过程中，检查这个接口都导入了什么资源，而且检查这些资源的渲染方式，从而定位到了漏洞。
   \_gitlab/lib/gitlab/github_import/importer/labels_importer.rb#16*
   ```
   def execute
     bulk_insert(Label, build_labels)
     build_labels_cache
   end
   ```
7. 注意到该攻击还绕过了 csp，绕过 csp 的方式是`jquery+<script>tag`，只有在渲染`<script>`标签可以绕过，其他的例如 onerror 不行，经过测试利用该漏洞能够绕过 script-src self csp，简直无敌。
   _gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#507_
   ```
   renderRow(item) {
       let criteria = {};
       let groupRowEl;
       switch (item.type) {
         case LEVEL_TYPES.DEPLOY_KEY:
           groupRowEl =
             this.accessLevel === ACCESS_LEVELS.PUSH ? this.deployKeyRowHtml(item, isActive) : '';
           break;
       }
       return groupRowEl;
     }
   ```
8. csp:

   **Self**: 仅仅执行同域名的 js 文件，所有 event handler 和`<script></script>`内的代码都不执行。`Jquery+<script>`标签可绕过
   **Unsafe-inline**: 所有 event handler 和`<script></script>`内的代码可以执行，但是出现 either a hash or nonce value，该条失效，就是说若存在'nonce-xxx'，那么 unsafe-inline 无效，event handler 和`<script>`内部代码都不执行。`Jquery+<script>`标签可绕过

9. 其中 csp 绕过的 jquery 代码如下：
   _app/assets/javascripts/gl_field_error.js#66_
   ```
   constructor({ input, formErrors }) {
     this.inputElement = $(input);
     this.inputDomElement = this.inputElement.get(0);
     this.form = formErrors;
     this.errorMessage = this.inputElement.attr('title') || __('This field is required.');
     this.fieldErrorElement = $(`<p class='${errorMessageClass} hidden'>${this.errorMessage}</p>`);
     this.state = {
       valid: false,
       empty: true,
       submitted: false,
     };
     this.initFieldValidation();
   }
   ```
   可以看到`${this.errorMessage}`没有过滤直接嵌入 jquery 元素中，该处也可以形成一个 regex，该代码在整个 gitlab 源码中只匹配到了上面片段：
   ```
   \$\([`\x27"][\s\S]{0,100}?<[\s\S]{3,200}?>[\s\S]{0,100}?[`\x27"]\)
   ```
   注意在 linux command 中，`'`需要 escape，方法是\x27 代替单引号，\x22 代替双引号，下面的双引号其实不需要 escape，例如，参考：[https://stackoverflow.com/a/65878993](https://stackoverflow.com/a/65878993)
   ```
   python ~/zero/DirBrute/findRegexInDir.py -d ~/discourse -f "\.js$" -r '\$\([`\x27\x22"]<[\s\S]{3,200}?>[`\x27\x22]\)' -n 'node_modules|test.js|spec.js'
   ```
10. 下面是负责导入 github 的后端 api 类，找到 github client，搜索 GithubImport::Client.new 来定位该类实例化的位置，可以找到两个位置，分别是：
    _app/controllers/import/github_controller.rb_
    _lib/api/import_github.rb_

    ![import_github](/assets/gitlab/1/import_github.png)

    其中 github*controller 中，host 无法被修改，因此默认为 github 的 api：
    \_app/controllers/import/github_controller.rb#108*

    ```
    def client
        @client ||= if Feature.enabled?(:remove_legacy_github_client)
                    Gitlab::GithubImport::Client.new(session[access_token_key])
                else
                    Gitlab::LegacyGithubImport::Client.new(session[access_token_key], **client_options)
                end
    end
    ```

    而 import*github.rb 中 host 可以修改，因此可以控制:
    \_lib/api/import_github.rb#14*

    ```
    def client
        @client ||= if Feature.enabled?(:remove_legacy_github_client)
                    Gitlab::GithubImport::Client.new(params[:personal_access_token], host: params[:github_hostname])
                else
                    Gitlab::LegacyGithubImport::Client.new(params[:personal_access_token], client_options)
                end
    end
    ```

    注意到，只能通过 github 来导入，如果选择用 git 或者其他方式导入，那么不会导入 labels。

11. 经过分析 import_github.rb 是 grape 构建的 api 接口，可以通过/v4/api 访问调用，参考：
    [https://github.com/ruby-grape/grape](https://github.com/ruby-grape/grape)

    _lib/api/api.rb_
    _config/routes/api.rb_
    _config/routes.rb#273_
    最终被 mount 挂载到主路由文件中

12. 导入测试，需要伪造一个假 github 服务器。首先通过导入正常的 github 仓库，并且对 gitlab 后端进行抓包，从而查看 gitlab 如何与 github 交互。

13. 首先在 gitlab 所在的 Ubuntu 服务器上安装 burpsuite 证书，参考[该链接](https://ubuntu.com/server/docs/security-trust-store)，安装 burpsuite 证书到系统 ca 根目录。然后设置终端 http_proxy 和 https_proxy 系统变量为 windows host 的 burpsuite 端口。启动 gitlab 服务后，rails 自动使用该代理。设置后，从 github 导入项目时，后端发送的请求就能够通过 burp 拦截。

    ```
    export https_proxy=http://10.15.0.147:8085
    export http_proxy=http://10.15.0.147:8085
    ```

    ![import1](/assets/gitlab/1/import1.png)

    ![import2](/assets/gitlab/1/import2.png)

14. 伪造 fake github server，需要一个公网服务器，并且在该服务器上安装 gitea 以便 gitlab 能导入仓库数据。node server 代码如下：

    [github fake server](vscode-local:/c%3A/Users/11593/AppData/Local/Temp/OneNote/16.0/Exported/%7B2E4B8080-29FE-40E1-B921-B593FF5E3AE4%7D/NNT/0/rb.zip)

    **gitea 配置**

    伪造的服务器需要配置 gitea 服务，并且需要和伪造请求中的 git 地址一样，这样 gitlab 会从伪造的服务器拉取代码和后续 labels 请求，否则还是会去 github 拉取。gitea 默认开启在 3000 端口，但是可通过 nginx proxy 代理到 80 端口，这一步是必要的。

15. fake github server 配置完成后，直接调用 gitlab 提供的 api 进行导入操作：

    ```
    curl --location 'http://127.0.0.1:3000/api/v4/import/github' \
    --header 'Accept: application/json, text/plain, */*' \
    --header 'Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5' \
    --header 'Cache-Control: no-cache' \
    --header 'Connection: keep-alive' \
    --header 'Cookie: perf_bar_enabled=true; preferred_language=en; hide_auto_devops_implicitly_enabled_banner_8=false; visitor_id=ae1ea916-faeb-458b-a6fe-e823e28e4946; frequently_used_emojis=smile%2Csmiley%2Cblush%2Cflag_wf%2Cman_dancing_tone3%2Cman_dancing_tone1; experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqTmlOVE0zWkRnMExXWm1ZV0V0TkRrd1pTMDVORGswTFRJell6VTVaalJqWmpjek15ST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--e03f99e2fe31888f17b1a38192c53e1a7c6eebe7; sidebar_collapsed=false; BetterErrors-2.9.1-CSRF-Token=7ebd9970-0ce3-4b4f-b4d6-0a96114c3c57; known_sign_in=cC9DbkxsUmZZVG1EeGZ3bGhlQmVXQlVqWnVKQ2k1aklucEc1QmpXTjQrUTBYQ2M1c2l4K0J4czRxclRVekNmZmFSeVRKaGduYzJ4eEQxa2ZRUmhzWEdZeXV0VTdyd21pMnlkd3ltdExOYWlEeHVDUlNwMjdvTEVKQWNvaFZGdFotLS9TNTRJc3gwWEdtRTYxamFOWmhUU3c9PQ%3D%3D--33ef27c41f5b2d1b3b3f81b201525cb25ad31280; hide_auto_devops_implicitly_enabled_banner_6=false; event_filter=push; remember_user_token=eyJfcmFpbHMiOnsibWVzc2FnZSI6Ilcxc3hYU3dpSkRKaEpERXdKRWR6TjNCbWJIaERiM2hYYW1WelpFcEVMakppTnk0aUxDSXhOekF3TmpFMk56VXdMakU0TURVeE5ETWlYUT09IiwiZXhwIjoiMjAyMy0xMi0wNlQwMTozMjozMC4xODBaIiwicHVyIjoiY29va2llLnJlbWVtYmVyX3VzZXJfdG9rZW4ifX0%3D--d9f8a3d3facd1ae216b64bae4390ee38fd8cd5e2; _gitlab_session_07baa7241726843883bf7ec3444d875952c2c2a722793cb27890cede722617b2=bbe97137c1f77a28d631400fc209d6b4; _gitlab_session_07baa7241726843883bf7ec3444d875952c2c2a722793cb27890cede722617b2=42172205f2e8b1d7619454840d139af6' \
    --header 'Pragma: no-cache' \
    --header 'Referer: http://127.0.0.1:3000/root/final5' \
    --header 'Sec-Fetch-Dest: empty' \
    --header 'Sec-Fetch-Mode: cors' \
    --header 'Sec-Fetch-Site: same-origin' \
    --header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36' \
    --header 'X-CSRF-Token: gmIiPkGG+9ZjV7zsBfslb4QjfYZSFDSszxzQy2/+RcfCFZtow6G8uogwP2lpmW4PIWuywI71kwZ5Ezvbw802/g==' \
    --header 'X-Requested-With: XMLHttpRequest' \
    --header 'sec-ch-ua: "Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"' \
    --header 'sec-ch-ua-mobile: ?0' \
    --header 'sec-ch-ua-platform: "Windows"' \
    --header 'Content-Type: application/json' \
    --data '{"repo_id":721517979,"personal_access_token":"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","new_name":"final7","target_namespace":"root","github_hostname":"http://8.134.66.236"}'
    ```

#### Tips

1. 该漏洞输入后端渲染漏洞，本来后端渲染数据是通过默认的 haml 模板用=进行渲染，这时会自动完成对数据的 escape，但是这里的漏洞采用了函数调用返回 html 字符串的形式，并且字符串在函数中标注了`HTML.chomp.html_safe`。
   _app/views/shared/\_label_row.html.haml_
   ```
   .label-name.gl-flex-shrink-0.gl-mt-2.gl-mr-3
     = render_label(label, tooltip: false)
   ```
   _gitlab/app/helpers/labels_helper.rb#266_
   ```
   def render_label_text(name, suffix: '', css_class: nil, bg_color: nil)
       <<~HTML.chomp.html_safe
           <span
           class="#{css_class}"
           data-container="body"
           data-html="true"
           #{"style=\"background-color: #{bg_color}\"" if bg_color}
           >#{ERB::Util.html_escape_once(name)}#{suffix}</span>
       HTML
   end
   ```
   果然后端是 html_safe 引发的问题。这样，变量中的 xss 代码就能够被嵌入了。
2. csp 绕过利用了前端 jquery 的漏洞，主要 gitlab 前端会扫描后端返回的 html 并且对某些标签进行 jquery 化的处理，很多漏洞都来源于这种机制。要绕过严格的 csp 不是简单的事情，但是 jquery 配合`<script></script>`html 注入，就可能够绕过 self 这样严格的限制。简直是最大的 bug，到 2023 年 11 月都没有修复。
