---
layout: post
title:  "中危：有道云笔记markdown模式渲染类图(classDiagram)存储型XSS漏洞"
date:   2024-03-16 10:26:18 +0800
categories: xss
---

## Name

> 网易有道云笔记markdown模式渲染classDiagram存在存储型XSS漏洞

## Weakness
> 存储型XSS

## Severity
> 中危

## URL
- POC网页: [https://note.youdao.com/s/2mc9Wfft](https://note.youdao.com/s/2mc9Wfft)
- 视频链接：POC视频链接：[https://pan.baidu.com/s/1GHxB356yrwWsILMcGRzk4A](https://pan.baidu.com/s/1GHxB356yrwWsILMcGRzk4A) 提取码：1314

## Key Payload


## Summary

网易有道云笔记可以创建markdown笔记，该笔记中可插入mermaid类图。在构建过程中，该种类图的节点名称可以注入xss payload，milkdown插件未将该payload进行过滤，而是直接渲染执行，造成存储型xss攻击。由于笔记可以分享，将分享链接发送给受害者后，即可控制受害者客户端，由此能够获取受害者的所有笔记和笔记内容，造成严重的用户隐私数据泄露。

### Detail

#### Trigger
1. 登录有道云笔记，[https://note.youdao.com/](https://note.youdao.com/). 点击左上侧“新建”，选择“Markdown”。

    ![newnote](/assets/images/youdaoyun/new-note.png)

2. 进入markdown笔记编辑器，点击“更多”，下拉菜单选择“类图”。

    ![more](/assets/images/youdaoyun/more.png)

3. 在类图的代码构建框中，填入以下payload，随即出现xss弹框。注意，xss在类图的节点名称中得到注入。
    
    ```
    classDiagram
    Class01 <|-- `AveryLongClass<img src='x' onerror=alert(document.domain)>`
    Class03 *-- Class04
    Class05 o-- Class06
    Class07 .. Class08
    Class01 : size()
    Class01 : int chimp
    Class01 : int gorilla
    ```
    xss弹框触发：

    ![xss](/assets/images/youdaoyun/xss.png)
    
4. 点击右上角分享按钮，生成分享链接。在新窗口打开分享的笔记链接，xss同样触发。

    分享笔记：

    ![share](/assets/images/youdaoyun/share.png)

    打开分享的笔记：

    ![sharexss](/assets/images/youdaoyun/share-xss.png)

5. 原因：Milkdown第三方插件的漏洞，经过测试在milkdown最新版本v7.3.5得到验证。已在官方仓库提交漏洞issue。详见：[https://github.com/Milkdown/milkdown/issues/1267](https://github.com/Milkdown/milkdown/issues/1267)

### Proof
请提供截图或视频

POC视频链接：[https://pan.baidu.com/s/1GHxB356yrwWsILMcGRzk4A](https://pan.baidu.com/s/1GHxB356yrwWsILMcGRzk4A)
提取码：1314

## Impact

该漏洞影响点击分享链接的用户，攻击者可以注入xss脚本获取受害者所有笔记ID和笔记内容，造成严重的敏感信息泄露。

## Patch advice

1. 对类图的node名称进行xss过滤

