---
layout: post
title:  "中危： LOFTER网页端存在敏感信息泄露"
date:  2022-07-06 09:11:45 +0800
categories: infoleaking
---

## Name

> LOFTER网页端存在用户信息敏感信息泄露

## Weakness

> 敏感信息泄露

## Severity

> 中危

## URL

- [https://www.lofter.com/](https://www.lofter.com/)

## Summary

LOFTER网页端存在敏感信息泄露问题。用户可以通过查看其关注列表来或者所有关注对象的手机号和QQ号。查看关注对象的URL为：[https://www.lofter.com/follow](https://www.lofter.com/follow)。用户点击该URL后，应用会调用接口：`https://www.lofter.com/dwr/call/plaincall/UserBean.getUserFollowingList.dwr`来获取关注对象敏感信息，该接口返回的响应中包含用户的手机号和QQ号等敏感信息。

#### Trigger
1. 用户查看关注对象。

    ![follow](/assets/lofter/follow.png)

2. 用BurpSuite抓包，可以看到接口请求返回敏感信息：

    ![followphone](/assets/lofter/followphone.png)

    ![followqq](/assets/lofter/followqq.png)

## Impact

在Lofter博客论坛上，通过关注任意用户，能够获取该用户的手机号和QQ号，造成指定对象的敏感信息泄露，影响恶劣。



