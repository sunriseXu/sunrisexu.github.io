---
layout: post
title: "Gitlab debugging: Using gitlab official docker to debug rails backend"
date: 2023-12-30 10:31:06 +0800
categories: debug
---

## Name

> Using gitlab official docker to debug rails backend

## Environment

1. `ps aux` 查看 gitlab 各种进程

   ![gitlabps](/assets/gitlab/1/gitlabps.png)

2. gitlab docker 的安装路径：`/opt/gitlab`

3. 启动脚本：`/opt/gitlab/bin`

4. gitlab rails 目录：`/opt/gitlab/embedded/service/gitlab-rails`

5. gitlab rails 启动命令：`/opt/gitlab/bin/gitlab-rails`
   `exec /opt/gitlab/embedded/bin/chpst -e /opt/gitlab/etc/gitlab-rails/env ${privilege_drop} -U ${gitlab_user}:${gitlab_group} /opt/gitlab/embedded/bin/bundle exec rails "$@"`

6. Docker gitlab 查看服务: `gitlab-ctl status`

## Steps

1. 停止 `unicorn` 服务，该服务负责运行 rails，后续我们手动启动：

   ```
   gitlab-ctl stop unicorn
   ```

2. 端口占用：3000 被 grafana 占用，后续 rails 将启动在 3000 端口，需要将 grafana 停止：

   ```
   gitlab-ctl stop grafana
   ```

3. 手动启动 rails

   ```
   cd /opt/gitlab/bin && ./gitlab-rails server
   ```

4. 修改 nginx 配置文件：`/var/opt/gitlab/nginx/conf/gitlab-http.conf` 。由于前端是编译好的，因此资源和 js 路径不再由 yarn 提供，而且由 nginx 提供，资源文件的重定向不变，但是位置需要提前。

   ```
   location /assets {
    proxy_cache gitlab;
    proxy_pass  http://gitlab-workhorse;
   }
   ```

   其他所有流量重定向为 puma 开启的本地端口 3000

   ```
   location / {
      proxy_pass http://localhost:3000/;
      proxy_cache off;
   }
   ```

   修改后重启 nginx：`gitlab-ctl restart nginx`

5. 添加 ruby 的 include 文件夹，将 ruby 变为开发版本，否则无法安装 gem，gem 需要 native 依赖。编译相同版本的 ruby，将编译后的 include 文件夹拷贝到路径：`/opt/gitlab/embedded/`

6. 进入 rails 目录`/opt/gitlab/embedded/service/gitlab-rails`，修改 Gemfile，添加 pry-byebug 库到主环境中，不加的话会报找不到 pry，例如

   ```
   gem 'pry-byebug', '~> 3.5.1'
   ```

   同 development 环境的 version 一致

7. 然后在应用 root 目录执行 `bundle install`，自动安装 `pry-byebug`

8. 在 break point 处下断点指令 `binding.pry`

9. 启动后端，由 puma 启动，默认端口 3000：
   ```
   ./gitlab-rails server -e development -b 0.0.0.0
   ```
   程序运行到断点会在当前终端停下
