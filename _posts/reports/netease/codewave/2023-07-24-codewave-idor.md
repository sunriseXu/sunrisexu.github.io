---
layout: post
title:  "高危：网易数帆codewave开发论坛能够修改他人帖子"
date:   2023-07-24 23:25:38 +0800
categories: idor
---

## Name

> 网易codewave开发论坛能够修改他人帖子，攻击者能够修改他人帖子，包括内容、赞数等

## Weakness
> 未授权的访问/权限绕过

## Severity
> 高危

## URL
- https://community.codewave.163.com/CommunityParent/Community

## Summary

网易codewave开发论坛能够修改他人帖子，攻击者能够通过PUT请求，设置任意用户ID，实现修改他人帖子，包括内容、赞数等攻击。

### Detail

#### Trigger
1. 打开并登录网易数帆-codewave开发论坛，[https://community.codewave.163.com/CommunityParent/Community](https://community.codewave.163.com/CommunityParent/Community)，打开任意帖子，通过burpsuite可以抓取到[https://community.codewave.163.com/api/posts](https://community.codewave.163.com/api/posts)的PUT请求，如下图所示：

    ![put](/assets/codewave/put.png)

2. 将该请求发送到burpsuite repeater，修改请求体中字段，包括：发帖人communityUserId、内容postsContent、时间、帖子点赞数likeNumber、收藏数、是否置顶帖postsTop（在论坛中置顶），是否删除帖子标记postsDelete（修改），ip地址，即可修改发帖内容。

    ![modify](/assets/codewave/modify.png)

3. 修改后如下图所示，poc url为：[https://community.codewave.163.com/CommunityParent/CommunityDetail?postsId=2660177059004928](https://community.codewave.163.com/CommunityParent/CommunityDetail?postsId=2660177059004928)：

    ![ipmodify](/assets/codewave/ipmodify.png)

4. 修改官方发布的帖子，仅改了点赞收藏数，poc url为：[https://community.codewave.163.com/CommunityParent/CommunityDetail?postsId=2636252305609984](https://community.codewave.163.com/CommunityParent/CommunityDetail?postsId=2636252305609984)

    ![koushiki](/assets/codewave/koushiki.png)
    
5. 伪造他人发帖，仅需要修改communityUserId字段为其他用户ID即可，亲测可行。

## Impact

典型未授权资源访问IDOR，用户能够伪造和修改任意帖子。



