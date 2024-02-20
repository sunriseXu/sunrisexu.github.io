---
layout: post
title:  "中危：网易天工网站wordpress主题discy未授权访问"
date:   2023-08-11 12:59:09 +0800
categories: wordpress
---

## Name

> 网易天工wlw.163.com wordpress主题discy存在未授权访问漏洞，普通用户能够修改整个网站

## Weakness
> 命令执行/代码执行

## Severity
> 中危

## URL
- https://wlw.163.com

## Key Payload

[完整post数据包下载](https://www.mediafire.com/file/pmoi0s9k2weq1fm/postData.txt/file)


## Summary

网易天工wlw.163.com wordpress主题discy存在未授权访问漏洞，普通用户能够修改整个网站，实现网站劫持。

### Detail
请按照逻辑对漏洞复现进行描述，提供危害说明和测试步骤。若使用工具复现漏洞，应提供工具详情
#### Trigger
1. 网易天工平台wlw.163.com利用wordpress建站，通过信息收集，发现该站用了主题discy

    ![version](/assets/tiangong/version.png)

2. 发现该主题存在未授权修改配置漏洞，能够修改整个网站样式和代码

    ![vulinfo](/assets/tiangong/vulinfo.png)


3. 于是注册网易天工普通账号，然后发送poc请求如下：

    ![payload](/assets/tiangong/payload.png)

4. 发现网站的皮肤已经被修改

    修改前：
    ![before](/assets/tiangong/before.png)
    修改后：
    ![after](/assets/tiangong/after.png)

5. 为了避免破坏网站，我自己安装了wordpress和discy主题，通过修改主题配置，添加js代码，可以进行xss攻击：

    ![xss](/assets/tiangong/xss.png)
        
6. 账户劫持的后续利用
    
    由于wlw.163.com是163域名，可以在该站注入xss脚本。可以串联其他163应用的登录跳转攻击，替换redirect跳转的url为wlw.163.com，受害者扫描登录（通过微信或者微博）后，就携带token跳转到wlw站点，此时，xss脚本就可以窃取token。由于wlw.163.com把我ip封了，这部分就不展示了。

### Proof
请提供截图或视频

[关于discy利用请看:https://www.youtube.com/watch?v=udxBGwW18zI](https://www.youtube.com/watch?v=udxBGwW18zI)


## Impact

wordpress主题过时，普通用户能够修改整个网站主题和页面内容，包括js内容，实现网站劫持。

## Patch advice

1. 升级该主题插件到最新版本

