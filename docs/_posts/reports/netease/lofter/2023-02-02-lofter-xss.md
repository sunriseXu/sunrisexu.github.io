---
layout: post
title:  "中危：LOFTER网页版发帖存在存储型XSS漏洞"
date:   2023-02-02 20:49:12 +0800
categories: xss
---

## 漏洞名称

> LOFTER网页版发帖存在存储型XSS漏洞

## 漏洞类型
> web漏洞-存储型XSS

## 危害等级
> 中危

## 漏洞URL
- [https://www.lofter.com/](https://www.lofter.com/)

## 漏洞描述

网易Lofter网页版的发帖功能存在存储型XSS漏洞，新建发帖，并且用burpsuit拦截post请求，修改帖子内容插入构造的XSS payload，即可完成攻击。另外，修改帖子请求也可以插入xss payload，完成攻击。

### 详细说明

#### 漏洞触发
1. 打开lofter首页，点击长文章发帖，进入发帖页面
    
    ![sign](/assets/lofter/post1.jpg)

    ![post2](/assets/lofter/post2.jpg)


2. 填写标题，上传图片，正文填写。点击右上角发布后，在弹出框中填写推荐语，选一个任意标签。此时打开burpsuite拦截功能，点击发布后。

    ![post3](/assets/lofter/post3.jpg)

    ![post4](/assets/lofter/post4.jpg)

3. 拦截的发帖请求，修改*/blog/0x5r33/new/long/*请求中的post参数longPostContent值为：`<a href="#"/OoNFOCus="alert(1)">clickme</a>`，进行url编码为：`%3Ca%20href%3D%22%23%22%2FOoNFOCus%3D%22alert%281%29%22%3Eclickme%3C%2Fa%3E`，发送即可完成攻击。另外，修改帖子同样可以完成攻击。

    ![payload](/assets/lofter/payload.jpg)

4. xss触发。

    ![xss](/assets/lofter/xss.jpg)

5. xss原因分析。

    > payload中：`<a href="#"/OoNFOCus="alert(document.cookie)">clickme</a>`，`/OoNFOCus`中，过滤掉了/O，剩下oNFOCus,刚好可以成为合法属性。


## 漏洞危害

在Lofter博客上存在存储型xss攻击，影响所有浏览该帖的用户。



