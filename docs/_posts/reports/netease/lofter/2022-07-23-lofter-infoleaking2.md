---
layout: post
title:  "中危：LOFTER网页端依然存在数个敏感信息泄露"
date:   2022-07-23 14:08:33 +0800
categories: infoleaking
---

## 漏洞名称

> LOFTER网页端依然存在数个敏感信息泄露

## 漏洞类型

> web漏洞-敏感信息泄露

## 危害等级

> 中危

## 漏洞URL

- [https://www.lofter.com/](https://www.lofter.com/)

## 漏洞描述

LOFTER网页端依然存在三个敏感信息泄露接口，只要用户在LOFTER首页点击“领域达人”和“标签达人”这两个功能，服务端便会返回推荐的用户的敏感信息，包含用户的手机号和微信号。隐私泄露接口，共3个：

1. **https://www.lofter.com/dwr/call/plaincall/TagBean.getRecommendBlogs.dwr**

2. **https://www.lofter.com/dwr/call/plaincall/UserBean.getRecommendBlogsByDomain.dwr**

3. **https://www.lofter.com/dwr/call/plaincall/TagBean.getBlogs.dwr**

#### 漏洞触发
1. 用户登录LOFTER网页端，网址为：[https://www.lofter.com](https://www.lofter.com)。

2. 登录后，进入“达人”页面：[https://www.lofter.com/explore?type=recommend&act=qbview_20130930_04](https://www.lofter.com/explore?type=recommend&act=qbview_20130930_04)。

    ![tatsujin](/assets/lofter/tatsujin.png)

3. 然后点击“领域达人”，网址为：[https://www.lofter.com/explore/?type=recommend](https://www.lofter.com/explore/?type=recommend)。然后用burp抓包，可以发现客户端发送的post请求：`https://www.lofter.com/dwr/call/plaincall/TagBean.getRecommendBlogs.dwr` 返回用户的敏感信息，包含手机号和微信号。

    ![tatsujin2](/assets/lofter/tatsujin2.png)

    ![leakwechat](/assets/lofter/leakwechat.png)

    ![leakphone](/assets/lofter/leakphone.png)

4. 紧接着，点击“领域达人”页面右侧的任何标签，例如”热门”，“女神”，“明星”等等，都会获取新的用户，因而触发另一个接口来获取用户信息，该接口为：`https://www.lofter.com/dwr/call/plaincall/UserBean.getRecommendBlogsByDomain.dwr`。同样，用burp抓包，可以获取到用户的手机号和微信号。

    ![hot](/assets/lofter/hot.png)

    ![hotphone](/assets/lofter/hotphone.png)

    ![hotwechat](/assets/lofter/hotwechat.png)

5. 最后，查看“达人”页面下的“标签达人”页面，url为：[https://www.lofter.com/explore/?type=tag&tag=%E6%91%84%E5%BD%B1](https://www.lofter.com/explore/?type=tag&tag=%E6%91%84%E5%BD%B1)。并且查看“标签达人”右侧的任何标签，都会触发接口：`https://www.lofter.com/dwr/call/plaincall/TagBean.getBlogs.dwr`。从而获取用户的手机号和微信号。

    ![tag](/assets/lofter/tag.png)

    ![tagwechat](/assets/lofter/tagwechat.png)

    ![tagphone](/assets/lofter/tagphone.png)

## 漏洞危害

在Lofter博客论坛上，能够直接获取部分用户的手机号和微信，影响恶劣。



