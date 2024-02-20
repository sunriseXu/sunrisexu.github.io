---
layout: post
title:  "中危：网易数帆-codewave开发论坛敏感信息泄露"
date:   2023-07-25 00:04:15 +0800
categories: idor
---

## Name

> 网易codewave开发论坛存在敏感信息泄露

## Weakness
> 敏感信息泄露

## Severity
> 中危

## URL
- [https://community.codewave.163.com/](https://community.codewave.163.com/)

## Summary

网易数帆论坛能够通过api接口获取用户的敏感信息，例如手机号，或者部分姓名。

### Detail

#### Trigger
1. 首先进入并且登录论坛，https://community.codewave.163.com/，然后点击右上角个人中心，如下图所示：

    ![login](/assets/codewave/login.png)

2. 同时在burpsuite中观察到*/api/loadUser* post请求，请求体为用户ID，响应的字段包含一个communityPhone字段包含加密的手机号。

    ![encphone1](/assets/codewave/encphone1.png)

    ![encphone2](/assets/codewave/encphone2.png)

3. 同时观察到在调用*/api/loadUser*后紧接着调用解密api，**/api/encrypt_tools/decryptWithBase64AndDes**，其中请求key为解密密钥，固定为：**951753123456789qetuoknbvcxz**，encryptedString为上一步的手机号密文。

    ![key1](/assets/codewave/key1.png)

    ![key2](/assets/codewave/key2.png)

4. 漏洞利用：任意找一个帖子，在burpsuite找到*/api/posts*的PUT请求，获取发帖人的communityUserId，例如*8bb15f6e8be14ed6b00cb7c753a40ddc*（仅测试用）。

    ![customer](/assets/codewave/customer.png)

5. 然后用 burpsuite repeater，通过*/api/loadUser*发送*8bb15f6e8be14ed6b00cb7c753a40ddc*，响应该用户的手机密文：**dKE5PeX7hT4YY8cd4mn6ug==**

    ![decphone](/assets/codewave/decphone.png)

6. 最后通过api：*/api/encrypt_tools/decryptWithBase64AndDes*解密手机号即可

    ![finaldec](/assets/codewave/finaldec.png)

7. 另外，当*/api/loadUser*的payload为空时，会响应20个用户的数据，并且手机号为明文。

    ![notenc](/assets/codewave/notenc.png)

## Impact

该漏洞使用了固定加解密密钥，并且用户能够在前端调用加解密请求，导致用户的手机号能够被解密，造成了大规模的用户敏感信息泄露。



