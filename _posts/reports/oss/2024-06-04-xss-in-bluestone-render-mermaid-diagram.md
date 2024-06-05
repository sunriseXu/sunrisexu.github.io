---
layout: post
title:  "XSS in Bluestone Electron App when rendering mermaid class diagram Leading to RCE"
date:  2024-06-04 10:31:06 +0800
categories: xss
---

### Summary
Due to outdated mermaid 10.0.2 is used to render diagrams, a XSS in class diagram is able to trigger, chained with insecure configuration of windows electron app, attacker is able to execute code in victims' local system.

### Details
Bluestone is using [mermaid 10.0.2](https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/package.json#L67) to render mermaid diagram. [This issue](https://github.com/Milkdown/milkdown/issues/1267#issuecomment-2018032986) have discussed the XSS in mermaid below 10.9.0 when rendering the node names of classDiagram. Specifically, The names of node are not fully sanitized which leads to  injection of XSS payload.

Besides, the electron app sets `nodeIntegration` to [`true`](https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/src/main/api.ts#L33) which is harmful, according to [this attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/electron-desktop-apps#introduction), a XSS can be escalated to execute command on victims' local system.

### PoC

1. Download latest Bluestone v0.22.0 windows electron app from [official repo](https://github.com/1943time/bluestone/releases/download/v0.22.0/Bluestone-win-x64.exe), and install the application:

2. Open the payload markdown file using the Bluestone app, the payload is following:

    ```
    classDiagram
    Class01 <|-- `AveryLngClas<img src='x' onerror=require('child_process').exec('calc');>`
    ```

2. The calculator poped up.

    ![rce](/assets/images/mermaid/bluestone-rce.png)

### Impact

Client side code execution. 


### Reference

[https://github.com/Milkdown/milkdown/issues/1267#issuecomment-2018032986](https://github.com/Milkdown/milkdown/issues/1267#issuecomment-2018032986)

### Occurence

[https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/package.json#L67](https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/package.json#L67)

[https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/src/main/api.ts#L33](https://github.com/1943time/bluestone/blob/07535f86adebe8f7f00c299ca60792189eff2a64/src/main/api.ts#L33)

### Mitigation

1. Upgrade the mermaid to latest version which is `10.9.1`.
2. Disable `nodeIntegration` in electron app.
