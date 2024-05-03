---
layout: post
title:  "中危：有道云笔记网页版思维导图存在存储型XSS漏洞"
date:   2024-03-17 10:26:18 +0800
categories: xss
---

## Name

> 有道云笔记网页版思维导图存在存储型XSS漏洞

## Weakness
> 存储型XSS

## Severity
> 中危

## URL
- POC网页: [https://note.youdao.com/s/JOK4BY08](https://note.youdao.com/s/JOK4BY08)


## Summary

有道云笔记`mindmap`思维导图能够插入`javascript`链接，受害者点击链接后可触发xss执行。

#### Trigger

1. 打开有道云网页版，新建脑图。添加分支主题，选中该分支，然后点击插入链接。

    ![mindmap1](/assets/images/youdaoyun2/mindmap1.png)

2. 输入任意url，开启burpsuite拦截请求：`POST /yws/api/personal/sync`。该请求将用户最新修改发送到后台。由于前端对url做了过滤，只能输入http协议，因此通过该请求修改成javascript协议。

    ![mindmap2](/assets/images/youdaoyun2/mindmap2.png)

    ![mindmap3](/assets/images/youdaoyun2/mindmap3.png)

3. 发送请求，修改url链接成功，链接连接后，xss触发。
    
    ![mindmap4](/assets/images/youdaoyun2/mindmap4.png)

### Proof
请提供截图或视频

POC链接：
[https://note.youdao.com/s/JOK4BY08](https://note.youdao.com/s/JOK4BY08)

视频：

链接：[https://pan.baidu.com/s/1KpYkdI1SHA2q21sij1mJpA](https://pan.baidu.com/s/1KpYkdI1SHA2q21sij1mJpA)

提取码：1314



## Impact

该漏洞影响点击分享链接的用户，攻击者可以注入xss脚本获取受害者所有笔记ID和笔记内容，造成严重的敏感信息泄露。



