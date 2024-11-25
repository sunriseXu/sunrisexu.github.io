---
layout: post
title: "Gitlab Html Injection in file search"
date: 2024-11-24 10:31:06 +0800
categories: xss
---

### Summary
Recently, I [searched for a file](https://docs.gitlab.com/ee/user/project/repository/files/#search-for-a-file) in my project hosted on [gitlab.com](https://gitlab.com). After I pressed the `T` button, the file names in my repo were rendered with a popup box which is different from older style (such as gitlab-ee 16.9.0). So I created new file with name `<img src=x onerror=alert()>`. After pressed the shortcut `T` again, the file name is rendered with a img, however no xss triggered. So I dig into it. 

First, in [command_palette_items.vue](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/super_sidebar/components/global_search/command_palette/command_palette_items.vue#L241), `getProjectFiles` fetch all filenames which is not sanitized. And then pass these file names to `search-item` for rendering.

```
async getProjectFiles() {
      if (!this.projectFiles.length) {
        this.loading = true;

        try {
          const response = await axios.get(this.projectFilesPath);
          this.projectFiles = response?.data.map(fileMapper.bind(null, this.projectBlobPath));
        } catch (error) {
          Sentry.captureException(error);
        } finally {
          this.loading = false;
        }
      }

      this.groups = [
        {
          name: PATH_GROUP_TITLE,
          items: this.filteredProjectFiles,
        },
      ];
    },
...
<template #list-item="{ item }">
    <search-item :item="item" :search-query="searchQuery" />
</template>
```

Then, in [`search_item.vue`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/super_sidebar/components/global_search/command_palette/search_item.vue#L27), the file name is passed to `highlight` for sanitizing and highlighting. After highlighted, the `highlightedName` is passed to `<span v-safe-html="highlightedName" class="gl-text-gray-900"></span>` for rendering.

```
highlightedName() {
      return highlight(this.item.text, this.searchQuery);
    }
...
// https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/super_sidebar/components/global_search/command_palette/search_item.vue#L49
<span class="gl-display-flex gl-flex-direction-column">
      <span v-safe-html="highlightedName" class="gl-text-gray-900"></span>
      <span
        v-if="item.namespace"
        v-safe-html="item.namespace"
        class="gl-font-sm gl-text-gray-500"
      ></span>
    </span>
```
However in [`highlight.js`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/lib/utils/highlight.js#L24), when `match` is empty string, the filename is return without any sanitizing which means if we search files without any query string, the raw html filename is rendered without sanitizing.
```
export default function highlight(string, match = '', matchPrefix = '<b>', matchSuffix = '</b>') {
  if (!string) {
    return '';
  }

  if (!match) {
    return string;
  }

  const sanitizedValue = sanitize(string.toString(), { ALLOWED_TAGS: [] });
...
```
In older verion of gitlab(such as gitlab-ee 16.9.0), the filename was sanitized properly in [`project_find_file.js`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/projects/project_find_file.js#L112)

```
renderList(filePaths, searchText) {

     ...
      let blobItemUrl = joinPaths(this.options.blobUrlTemplate, escapeFileUrl(filePath));

      if (this.options.refType) {
        const blobUrlObject = new URL(blobItemUrl, window.location.origin);
        blobUrlObject.searchParams.append('ref_type', this.options.refType);
        blobItemUrl = blobUrlObject.toString();
      }
      const html = ProjectFindFile.makeHtml(filePath, matches, blobItemUrl);
      results.push(this.element.find('.tree-table > tbody').append(html));
    }

    this.element.find('.empty-state').toggleClass('hidden', Boolean(results.length));

    return results;
  }
```
I tried to find a bypass to `v-safe-html` but failed,  the sanitizer is Dompurify 3.1.5 which doesn't have any bypassing. But in [Dompurify 3.1.3](https://github.com/cure53/DOMPurify/releases/tag/3.1.3),  a mXSS was found which may have ability to inject xss in this case, but after I dig into that, the mutation need `//` comment in html attributes which is not valid filename. 

### Steps to reproduce

1. Go to gitlab.com and in your repository create a new file using Gitlab UI, using the filename such as `<img src=x onerror=console.log(1)>`, with random file content.
2. Commit changes to finish creating file. 
3. Press key `T` to trigger the search box, the broken img is rendered.

### Impact

If bypass is found in Dompurify, victims may trigger the xss in a malicious repository when they try to find files in that repo in self-host gitlab instance with csp disabled.

### What is the current *bug* behavior?

Files with raw html names are rendered without sanitizing when searching files.

### What is the expected *correct* behavior?

Files with raw html names are rendered sanitized properly when searching files.

### Relevant logs and/or screenshots

![img2](/assets/gitlab/file-search/gitlab-html-injection2.png)


#### Results of GitLab environment info

```
System information
System:
Proxy:          no
Current User:   git
Using RVM:      no
Ruby Version:   3.1.5p253
Gem Version:    3.5.11
Bundler Version:2.5.11
Rake Version:   13.0.6
Redis Version:  7.0.15
Sidekiq Version:7.1.6
Go Version:     unknown

GitLab information
Version:        17.1.0-pre
Revision:       ab5fd7f7792
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     PostgreSQL
DB Version:     14.11
URL:            http://10.15.0.5
HTTP Clone URL: http://10.15.0.5/some-group/some-project.git
SSH Clone URL:  git@10.15.0.5:some-group/some-project.git
Elasticsearch:  no
Geo:            no
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:        14.35.0
Repository storages:
- default:      unix:/var/opt/gitlab/gitaly/gitaly.socket
GitLab Shell path:              /opt/gitlab/embedded/service/gitlab-shell

Gitaly
- default Address:      unix:/var/opt/gitlab/gitaly/gitaly.socket
- default Version:      17.0.0-rc2-314-g68ace2015
- default Git Version:  2.45.1
```

## Impact

If bypass is found in Dompurify, victims may trigger the xss in a malicious repository when they try to find files in that repo in self-host gitlab instance with csp disabled.