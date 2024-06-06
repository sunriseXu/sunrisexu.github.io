---
layout: post
title:  "Hackerone: Store XSS in Gitness markdown comment editor($100)"
date:  2024-05-11 10:31:06 +0800
categories: xss
---

## Name

> Store XSS in Gitness markdown comment editor

## Weakness

> CWE-79: Cross-site Scripting (XSS) - Stored

## Severity

> High (7.3)


## Description

An attacker can send malicous description when creating a pull request, or comment with malicious payload bellow an existing PR. Due to improper using of [react-markdown-preview component](https://github.com/uiwjs/react-markdown-preview?tab=readme-ov-file#security), html tags is not fully sanitized, and can be rendered with xss payload. 

In [MarkdownViewer.tsx rehypeRewrite](https://github.com/harness/gitness/blame/e31f33addea310b28a21ad1e05ab661acd163ef8/web/src/components/MarkdownViewer/MarkdownViewer.tsx#L144). The sanitizing is not sufficient, only `a, input, checkbox, link` is sanitized, the rest html can be injected arbitrarily.

```
<MarkdownPreview
    key={flag ? hash : 0}
    source={markdown}
    skipHtml={true}
    warpperElement={{ 'data-color-mode': darkMode ? 'dark' : 'light' }}
    rehypeRewrite={(node, _index, parent) => {
        if ((node as unknown as HTMLDivElement).tagName === 'a') {
        if (parent && /^h(1|2|3|4|5|6)/.test((parent as unknown as HTMLDivElement).tagName)) {
            parent.children = parent.children.slice(1)
        }
        ...
        }
        if (
        (node as unknown as HTMLDivElement).tagName === 'input' &&
        (node as Unknown as Element)?.properties?.type === 'checkbox'
        ) {
        const lineNumber = parent?.position?.start?.line ? parent?.position?.start?.line - 1 : 0
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const element = node as any
        element.properties['data-line-number'] = lineNumber.toString()
        element.properties.disabled = !inDescriptionBox
        }
    }}
    rehypePlugins={[
        [rehypeVideo, { test: /\/(.*)(.mp4|.mov|.webm|.mkv|.flv)$/, details: null }],
        [rehypeExternalLinks, { rel: ['nofollow noreferrer noopener'], target: '_blank' }]
    ]}
/>
```

## Proof of Concept

1. Create an gitness server, using following command from official tutorial:

    ```
    docker run -d \
    -p 3000:3000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp/gitness:/data \
    --name gitness \
    --restart always \
    harness/gitness
    ```

2. Create an empty repository, such as: `xss-test`

    ![repo](/assets/images/bughunter/gitness/create-repo.png)

3. Open `Branches` section, new branch `branch2`. After create new branch, checkout to `branch2` and create new file `test` with any content, and commit the change.

    ![branch](/assets/images/bughunter/gitness/new-branch.png)

4. Open `Pull Requests` section, create new pull request, set base to `main` branch and compare to `branch2` branch. In `Description` markdown editor, send payload `<iframe srcdoc="<script>alert(document.cookie)</script>"></iframe>`, and press the button `create pull request`. After creating the pr, an alert should pop up.

![branch](/assets/images/bughunter/gitness/pr1.png)

![branch](/assets/images/bughunter/gitness/alert.png)


## Impact

Anyone who is capable to comment on pr or create pr can post a comment on a public project pull requests and injecting the xss.

## Reference

[https://github.com/uiwjs/react-markdown-preview?tab=readme-ov-file#security](https://github.com/uiwjs/react-markdown-preview?tab=readme-ov-file#security)

FIX:
[https://github.com/harness/gitness/commit/49f3bf151e89d59bad60b3d41b1341d7c5b66b17](https://github.com/harness/gitness/commit/49f3bf151e89d59bad60b3d41b1341d7c5b66b17)

## Occurrences

[https://github.com/harness/gitness/blob/e31f33addea310b28a21ad1e05ab661acd163ef8/web/src/components/MarkdownViewer/MarkdownViewer.tsx#L141](https://github.com/harness/gitness/blob/e31f33addea310b28a21ad1e05ab661acd163ef8/web/src/components/MarkdownViewer/MarkdownViewer.tsx#L141)