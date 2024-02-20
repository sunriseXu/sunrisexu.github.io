---
layout: post
title:  "Replication: Gitlab Stored XSS in markdown when redacting references"
date:  2023-12-05 10:31:06 +0800
categories: xss
---

## Name

> Gitlab Stored XSS in markdown when redacting references

## Weakness

> XSS

## Severity

> 高危

## Environment

> Gdk version:
1b0e37a87f64ea5aad3ec9af1de9d563ca2a6a44
Gitlab version
v12.9.2-ee
Ubuntu version
18.04

> 原文：[https://hackerone.com/reports/836649](https://hackerone.com/reports/836649)

## URL

## Summary

漏洞函数`redacted_node_content`负责渲染markdown的reference部分，其中node的`data-original`属性能够被注入xss，导致`#{content}`包含该xss返回前端得到执行。
*lib/banzai/reference_redactor.rb:75*
```
def redacted_node_content(node)
      original_content = node.attr('data-original')
      link_reference = node.attr('data-link-reference')
      # Build the raw <a> tag just with a link as href and content if
      # it's originally a link pattern. We shouldn't return a plain text href.
      original_link =
        if link_reference == 'true'
          href = node.attr('href')
          content = original_content
          %(<a href="#{href}">#{content}</a>)
        end
```

## Code Review

### pre-byebug

由于ruby版本比较老旧，无法使用vscode插件进行调试，选择pre-byebug手动调试。首先在代码行前插入pre-byebug断点binding.pry，然后使用`bin/rails server`跑起来，遇到断点则自动停下。
尝试关闭log开启调试，`rails server --help`知道，加上后缀可以关闭log
`bin/rails server --no-log-to-stdout`
另外还有puma的日志需要关闭：
*lib/gitlab/cluster/puma_worker_killer_initializer.rb:33* 添加：（见[https://github.com/zombocom/puma_worker_killer](https://github.com/zombocom/puma_worker_killer)）
`config.reaper_status_logs = false`

1. 通过drawio画出[函数流关系图](https://drive.google.com/file/d/1RuaQELwDr-kQDS1XHNpDNi8Xh7EQ4WZI/view?usp=sharing)。找到部分触发该漏洞函数的controller。

### Review
    
1. 直接通过markdown preview渲染来实时获取渲染片段。经过调试发现，用户的输入首先会进行html化，然后进行渲染。
    *app/controllers/concerns/preview_markdown.rb*
    ```
    render json: {
          body: view_context.markdown(result[:text], markdown_context_params),
          references: {
            users: result[:users],
            suggestions: SuggestionSerializer.new.represent_diff(result[:suggestions]),
            commands: view_context.markdown(result[:commands])
          }
        }
    ```
    *app/helpers/markup_helper.rb:99*
    ```
    def markdown(text, context = {})
        return '' unless text.present?
        context[:project] ||= @project
        context[:group] ||= @group
        html = markdown_unsafe(text, context)
        # byebug
        prepare_for_rendering(html, context)
      end
    ```
    从preview的调用栈，可以看到首先将markdown转为html，然后再对html进行处理。`markdown_unsafe`主要负责前中期html转换，`prepare_for_rendering`负责html的后期处理，当然问题出在这个后期处理上。
2. 通过函数名推断，输入reference相关markdown，可以触发漏洞函数，查询文档可以得知reference的markdown语法。[https://docs.gitlab.com/ee/user/markdown.html#gitlab-specific-references](https://docs.gitlab.com/ee/user/markdown.html#gitlab-specific-references)。（ps:分析项目还是要结合文档进行分析，不然什么时候才时候头呢？）
3. 例如输入`@root`，这是一个用户引用markdown，会引用root这个用户，那么第一个函数`markdown_unsafe`会返回html:
    ```
    <p data-sourcepos="1:1-1:5" dir="auto">
    <a href="/root" data-user="1" data-reference-type="user" data-container="body" data-placement="top" data-html="true" class="gfm gfm-project_member" title="Administrator">
    @root</a>
    </p>
    ```
    但是从漏洞函数分析，html需要包含属性`data-origin`和`data-reference-link`这个两个值才行，特别是`data-reference-link`是必须的。
4. 从文字着手分析，应该是包含链接的reference，从文档查看，应该是：`[README](doc/README.md#L13)`
5. 经过代码审计，发现gitlab特定的markdown有两种输入方式，分别是markdown和html格式，html由markdown渲染而来，因此用户输入该html也能达到同等渲染效果，但是html的输入扩大了攻击面。
    *gitlab-v12.9.2-ee/lib/banzai/pipeline/gfm_pipeline.rb*
    ```
    # These filters transform GitLab Flavored Markdown (GFM) to HTML.
    # The nodes and marks referenced in app/assets/javascripts/behaviors/markdown/editor_extensions.js
    # consequently transform that same HTML to GFM to be copied to the clipboard.
    # Every filter that generates HTML from GFM should have a node or mark in
    # app/assets/javascripts/behaviors/markdown/editor_extensions.js.
    # The GFM-to-HTML-to-GFM cycle is tested in spec/features/copy_as_gfm_spec.rb.
    ```
    因此直接对markdown渲染后的元素进行拷贝作为基准payload，下面拷贝了引用issue的markdown`#1`所渲染的html:
    ```
    <a href="http://127.0.0.1:3000/xss/xxss/-/issues/1" data-original="#1" data-link="false" data-link-reference="false" data-project="20" data-issue="436" data-reference-type="issue" data-container="body" data-placement="top" data-html="true" title="xss">#1&lt;img src=x&gt;</a>
    ```
    payload中`#1&lt;img src=x&gt;`是主要部分。该部分原本是escape后的字符串，但是在后端处理时将其赋值给了属性值，而Nokogiri库自动对属性值进行unescape。
6. ruby库Nokogiri解析html字符串时，会把属性中html encoded字符进行unencoded，最终造成注入问题。
    *lib/banzai/filter/reference_filter.rb:132* 该函数将html字符串替换到node对象中，其中html字符串包含escape的属性值。
    ```
    def replace_link_node_with_href(node, link)
        html = yield
        binding.pry
        node.replace(html) unless html == link
    end
    ```
    node.replace是nokogiri库调用，该函数对html字符串进行解析，构建html node对象:
    */home/kali/.rvm/gems/ruby-2.6.5/gems/nokogiri-1.10.8/lib/nokogiri/xml/node.rb:477*
    ```
    node_set = in_context(contents, options.to_i)
    ```
    其中解析字符串的函数由nokogiri的[c函数](https://github.com/sparklemotion/nokogiri/blob/9aebcc669a7028e4faad1fc8b53cf46a2f2320ba/ext/nokogiri/xml_node.c#L2152)实现。该函数负责解析属性和值，并且将属性值的html编码进行unescape。
    
### Step to reproduce
