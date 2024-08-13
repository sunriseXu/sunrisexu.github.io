---
layout: post
title:  "高危：网易云课堂ai设计工坊存在文件读取漏洞"
date:   2024-03-24 10:26:18 +0800
categories: LFI
---

## Name

> 网易云课堂ai设计工坊存在文件读取漏洞

## Weakness
> LFI

## Severity
> High, 9.5

## Detail

网易云课堂ai设计工坊是开源的stable diffusion webui搭建而成，其中引用了sd-webui-prompt-all-in-one插件。该插件在加载js或者css文件时，没有对其中一个web接口的文件路径进行过滤，攻击者可以提供任意文件路径，从而实现任意文件读取。通过读取/etc/passwd、/home/study/.bash_history等敏感文件，笔者能够获取该网站服务器的bash记录，以及该网站的对象存储的accessToken等敏感信息。

请看漏洞POC：

- 链接：https://pan.baidu.com/s/1gjmX_vYA_xwHeH26DDjsEA 
- 提取码：1314




## Steps

1. 进入网易云课堂，选择AI设计工坊，然后点击创作，进入stable diffusion webui网站。开启burpsuite，记录打开该网站的流量。或者直接输入该网站网址：https://sd.study.163.com/paintingStudioFree/?__theme=dark

    ![1](/assets/youdaoai/LFI1.png)

    ![2](/assets/youdaoai/LFI2.png)

    ![3](/assets/youdaoai/LFI3.png)

2. 通过分析burpsuite拦截的url，笔者发现一个url可能有安全隐患：https://sd.study.163.com/paintingStudioFree/physton_prompt/styles?file=tippy.css 通过在网上搜索physton_prompt关键字，定位到插件： https://github.com/Physton/sd-webui-prompt-all-in-one

    ![4](/assets/youdaoai/LFI4.png)

3. 尝试改变file参数的文件路径为/etc/passwd，发现返回服务器的相应文件！注意cookie这里进行了删除，但是需要登陆者的cookie。

    ![5](/assets/youdaoai/LFI5.png)

4. 漏洞点位分析：该漏洞源于开源插件 https://github.com/Physton/sd-webui-prompt-all-in-one 暴露的web接口没有对file参数值进行过滤，python通过join直接能够读取任意文件。

    [on_app_started.py#L358](https://github.com/Physton/sd-webui-prompt-all-in-one/blob/2a32817694036517d9a05ed9b2048d2fbe2f5f26/scripts/on_app_started.py#L358)

    [styles.py#L10](https://github.com/Physton/sd-webui-prompt-all-in-one/blob/2a32817694036517d9a05ed9b2048d2fbe2f5f26/scripts/physton_prompt/styles.py#L10)

## Impacts

1. 获取.bash_history操作记录
2. 通过审查操作记录，发现某对象存储的token和密码