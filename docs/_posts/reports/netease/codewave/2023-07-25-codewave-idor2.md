---
layout: post
title:  "中危：网易数帆-codewave开发论坛未授权修改用户信息"
date:   2023-07-25 00:48:21 +0800
categories: idor
---

## 漏洞名称

> 网易数帆-codewave开发论坛未授权修改用户信息

## 漏洞类型
> web漏洞-敏感信息泄露

## 危害等级
> 中危

## 漏洞URL
- [https://community.codewave.163.com/](https://community.codewave.163.com/)

## 漏洞描述

网易数帆论坛通过该论坛提供的修改用户信息功能，能够修改任意用户的信息，包括用户名、手机号、用户图片、用户title、用户企业等信息。

### 详细说明

#### 漏洞触发
1. 在论坛注册两个账号，[https://community.codewave.163.com/](https://community.codewave.163.com/)，进入用户中心时打开chrome devtool，在网络请求中找到*/api/loadUser*请求，可以看到用户个人信息：
    
    用户1：Codewave333，注意记录id和communityUserId

    ![user1](/assets/codewave/user1.png)

    用户2：115****551x,注意记录id和communityUserId

    ![user2](/assets/codewave/user2.png)

2. 点击用户1的用户中心进入用户页面，修改用户名，点击确定后，burpsuite抓取到PUT请求 */api/community-user*。

    ![modifyuser](/assets/codewave/modifyuser.png)

3. 将该请求发送到repeater，替换id和communityUserID为用户2的相应值，发送，检查账户2信息，已经修改成功。

    ![infomodified1](/assets/codewave/infomodified1.png)

    ![infomodified2](/assets/codewave/infomodified2.png)

4. 修改他人账户为官方账户。

    ![impersonation](/assets/codewave/impersonation.png)


## 漏洞危害

该漏洞能够修改任意用户的资料，包括头像、手机号、头衔等。攻击者可能将自己修改为官方账户，实现信息欺诈。



