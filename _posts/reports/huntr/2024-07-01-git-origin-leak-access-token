---
layout: post
title:  "Git remote origin leaks user access token(Invalid)"
date:  2024-07-01 10:31:06 +0800
categories: file-overwrite
---

## Name

> Git remote origin leaks user access token

## Version

> 2.45.2

## Description

Lots of people are using personal access token to clone their private repository. To use a access token, you can include your username and token in https url to clone projects on github, gitlab or any other DevOps Platform:

```
git clone https://<username>:<token>@github.com/username/repository.git
```

However, we can get the token back easily by just using `git remote get-url origin`.

```
cd privateProject
git remote get-url origin
> https://username:ghp_xxxxx@github.com/username/repository.git
```

This can be dangerous, because we often run third party tools in our private repository. If a malicious tool runs `git remote get-url origin`, it can steal our personal access token of github or gitlab. In this case, our github/gitlab will be controlled by attackers which can have severe consequences.

I found this issue during code auditing via [safety tool](https://github.com/pyupio/safety). After scanning a project using `safety check -r requirements.txt --save-json test.json`, safety saved results into `test.json` file. However, when I looked into `test.json`, I found my personal access token in this file. 

```
"report_meta": {
    "scan_target": "files",
    "scanned": [
        "/home/kali/huntr/azure-sdk-for-python/tools/azure-sdk-tools/ci_tools/versioning/requirements.txt"
    ],
    "target_languages": [
        "python"
    ],
    "git": {
        "branch": "main",
        "tag": "",
        "commit": "b182b0c4f9d07d18f118130bc941c3b7a75667b1",
        "dirty": false,
        "origin": "https://outh2:ghp_xxxx@github.com/sunriseXu/xxxx.git"
    },
}
```

So, I looked into the source code of safety. The class [`GIT`](https://github.com/pyupio/safety/blob/f15d7908d27fd887dcc6b31237b8e3df79a9359b/safety/scan/util.py#L49) is responsible for collecting repository information in current repo where safety runs.

```
class GIT:
    ORIGIN_CMD: Tuple[str, ...] = ("remote", "get-url", "origin")
    def __run__(self, cmd: Tuple[str, ...], env_var: Optional[str] = None) -> Optional[str]:
        if env_var and os.environ.get(env_var):
            return os.environ.get(env_var)

        try:
            return subprocess.run(self.git + cmd, stdout=subprocess.PIPE, 
                                    stderr=subprocess.DEVNULL).stdout.decode('utf-8').strip()
        except Exception as e:
            LOG.exception(e)
        
        return None
    def origin(self) -> Optional[str]:
        # get the origin of repository
        return self.__run__(self.ORIGIN_CMD, env_var="SAFETY_GIT_ORIGIN")
```

## Impact

This can have severe consequences. **Any** tools running in private repositories have ability to steal personal access token if the token is written in git remote url explicitly. Git should mask user's access token when using cli command `git remote get-url origin`.



