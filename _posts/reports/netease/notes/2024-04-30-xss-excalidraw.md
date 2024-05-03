---
layout: post
title:  "中危：有道云笔记网页版白板存在存储型XSS漏洞"
date:   2024-04-30 10:26:18 +0800
categories: xss
---

## Name

> 有道云笔记网页版白板存在存储型XSS漏洞

## Weakness
> 存储型XSS

## Severity
> 中危

## URL
- POC网页: [https://note.youdao.com/s/5DooTGzS](https://note.youdao.com/s/5DooTGzS)


## Summary

有道云白板使用过时`excalidraw`，该插件存在已知xss漏洞：给任意白板元素添加链接时，没有过滤链接的协议，攻击者能够构造javascript链接，受害者点击元素后触发javascript payload执行

### Detail

#### Trigger
1. 打开有道云网页版，新建白板，在白板中画任意元素。

2. 选定该元素，点击添加添加链接，链接框填写如下payload：`javascript://%0aalert(document.cookie)`

    ![excalidraw1](/assets/images/youdaoyun2/excalidraw1.png)

3. 点击元素链接后，xss触发。分享给他人，只需点击一次即可触发xss。
    
    ![excalidraw2](/assets/images/youdaoyun2/excalidraw2.png)

    ![excalidraw3](/assets/images/youdaoyun2/excalidraw3.png)


### Proof
请提供截图或视频

POC链接：
https://note.youdao.com/s/5DooTGzS

参考：[https://github.com/advisories/GHSA-v7v8-gjv7-ffmr](https://github.com/advisories/GHSA-v7v8-gjv7-ffmr)

## Impact

该漏洞影响点击分享链接的用户，攻击者可以注入xss脚本获取受害者所有笔记ID和笔记内容，造成严重的敏感信息泄露。

## Patch advice

1. 升级渲染excalidraw插件到最新版本

