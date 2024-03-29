---
layout: post
title:  "Reproduction: Gitlab CSP-bypass XSS in project settings page"
date:  2023-11-01 10:31:06 +0800
categories: xss
---

## Name

> Gitlab CSP-bypass XSS in project settings page

## Weakness

> XSS

## Severity

> 高危

## Environment

> gitlab版本：14.5.2-ee

> 原文：[https://hackerone.com/reports/1588732](https://hackerone.com/reports/1588732)

## URL



## Summary

gitlab前端jquery js渲染漏洞，js未对用户输入进行校验，而直接利用`${}`构造html，嵌入网页后触发xss

#### Code Review

##### 前端渲染部分

1. *gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#534*

    ```
    deployKeyRowHtml(key, isActive) {
        const isActiveClass = isActive || '';
        return `
          <li>
            <a href="#" class="${isActiveClass}">
              <strong>${key.title}</strong>
              <p>
                ${sprintf(
                  __('Owned by %{image_tag}'),
                  {
                    image_tag: `<img src="${key.avatar_url}" class="avatar avatar-inline s26" width="30">`,
                  },
                  false,
                )}
                <strong class="dropdown-menu-user-full-name gl-display-inline">${escape(
                  key.fullname,
                )}</strong>
                <span class="dropdown-menu-user-username gl-display-inline">${key.username}</span>
              </p>
            </a>
          </li>
        `;
      }
    ```
    其中`key.title`没有过滤直接添加到html中。

2. 该函数被*gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#29*行调用，进而定位到*gitlab/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#396*。

    ```
    renderMenu(html) {
        if (this.options.renderMenu) {
          return this.options.renderMenu(html);
        }
        return $('<ul>').append(html);
      }
    ```
    最终通过jquery进行直接渲染，从用户输入注入到html字符串中，到最终的渲染jquery的append函数，构成了完整的xss攻击。

##### 后端存储部分

1. 首先接受表单的输入，并且发送给后台，表单的创建通过rails默认的`form_for`完成，路径为：gitlab/app/views/admin/deploy_keys/new.html.haml
2. `form_for`的默认action为：如果实例未创建，那么默认为post方法创建实例；如果以创建，那么默认为更新post方法。注意到form_for没有对用户输入进行过滤。

    ![formfor](/assets/gitlab/1/formfor.png)

3. 那么对于接受用户输入的前端，可以直接搜索form_for方法来进行定位.
4. 对于后端接受post请求创建新实例的文件为：*gitlab/app/controllers/admin/deploy_keys_controller.rb*，对应到create方法，该方法调用了另一个create：*gitlab/app/services/deploy_keys/create_service.rb*
    ```
    module DeployKeys
        class CreateService < Keys::BaseService
        def execute(project: nil)
            DeployKey.create(params.merge(user: user))
        end
        end
    end
    ```
5. Module DeployKey的create方法为内置方法，用于创建一个新的实例，可以看到该处也没有进行用户输入过滤。本来模型在变量定义时就会规定筛选动作，特别是对于应该合法的变量，但是本例中的变量title不应该被筛选，而类似上例中的color属性只能局限为某些颜色，为了防止用户输入随机值，所以采用了筛选机制，筛选机制是匹配失败则后端返回报错。
6. 至此，从用户输入到存入后端数据库这一过程都没有进行输入过滤。接下来看一下拉取该输入到前端过程是否有过滤。

##### 前端拉取数据部分

1. 定位到gl_dropdown.js负责对该下拉列表进行处理，逻辑是：前端对某些下拉菜单类进行jquery定位，然后对其进行拦截，注册监听click方法和相关的js动作，例如显示下拉菜单和网络请求
2. Gl_dropdown.js负责在用户点击下拉菜单时，请求后台数据，并且将返回的数据进行渲染。渲染的过程在本节的最开始已经分析。这里分析请求数据到渲染这一过程：
    a. 首先gl_dropdown.js执行opened(e)函数，然后执行this.remote.execute();获取后台数据
3. 首先，请求数据的url不在DeployKey controller中，而是在另一个controller类中，该方法直接返回DeployKey模型的数据，在后端没有进行过滤，以json结构返回。
4. 返回后，通过this.options.success方法对json数据进行渲染，并且请求体获取后没有对json对象的字段进行过滤。
5. 至此，分析结束。不懂的是下来菜单如何挂载到后端渲染的网页上的，这是在前端的js脚本进行挂载的。
6. 原始的显示部分对于keytitle是有过滤的，这一部分是后端渲染，默认使用haml的=会对之后的字符串进行escape，所以这里的后端渲染是安全的。

##### 基于函数流分析

开始基于函数流和基于数据流的分析，基于数据流分析是因为函数流分析是模糊分析，数据流则更为细致。

1. 函数parseData调用renderData，经由renderMenu，最终实现UI渲染：
    *gitlab/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#238*
    ```
    parseData(data) {
        let groupData;
        let html;
        this.renderedData = data;
        if (this.options.filterable && data.length === 0) {
            // render no matching results
            html = [this.noResults()];
        }
        // Handle array groups
        else if (isObject(data)) {
            this.renderData(groupData, name).map((item) => html.push(item));
        });
        } else {
            // Render each row
            html = this.renderData(data);
        }
        // Render the full menu
        const fullHtml = this.renderMenu(html);
        return this.appendMenu(fullHtml);
    }
    ```
    *gitlab/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#396*
    ```
    renderMenu(html) {
        if (this.options.renderMenu) {
          return this.options.renderMenu(html);
        }
        return $('<ul>').append(html);
      }
    ```
2. 函数renderData负责传入数据进行渲染：
    *gitlab/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#272*
    ```
    renderData(data, group) {
        return data.map((obj, index) => this.renderItem(obj, group || false, index));
      }
    ```
3. 回到gl_dropdown.js文件，可以看到引用了render.js的默认item函数，并且将options传递，注意options包含renderRow函数的句柄：
*gitlab/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#428*
    ```
    import renderItem from './render';
      renderItem(data, group, index) {
        return renderItem({
          instance: this,
          options: {
            ...this.options,
            icon: this.icon,
          },
          data,
        });
      }
    ```
4. 在deprecated_jquery_dropdown文件夹中搜索renderRow关键字，定位到render.js文件调用了该函数，最终由默认函数item调用了renderRow函数：*gitlab/app/assets/javascripts/deprecated_jquery_dropdown/render.js#150*
    ```
    function getOptionRenderer({ options, instance }) {
      return options.renderRow && ((li, data) => options.renderRow(data, instance));
    }
    function getRenderer(data, params) {
      return renderersByType[data.type] || getOptionRenderer(params) || renderLink;
    }
    export default function item({ data, ...params }) {
      const renderer = getRenderer(data, params);
      const li = document.createElement('li');
      if (shouldHide(data, params)) {
        hideElement(li);
      }
      return renderer(li, data, params);
    }
    ```
5. 定位到initDeprecatedJQueryDropdown函数所在的文件，可以看到类被绑定到$dropdown元素中
    *gitlab/app/assets/javascripts/deprecated_jquery_dropdown/index.js#8*
    ```
    export default function initDeprecatedJQueryDropdown($el, opts) {
      // eslint-disable-next-line func-names
      return $el.each(function () {
        if (!$.data(this, 'deprecatedJQueryDropdown')) {
          $.data(this, 'deprecatedJQueryDropdown', new GitLabDropdown(this, opts));
        }
      });
    }
    ```
6. 函数initDropdown中的函数initDeprecatedJQueryDropdown获取了renderRow函数的地址，当作句柄。
    *gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#31*
    ```
    initDropdown() {
        const { onSelect, onHide } = this.options;
        initDeprecatedJQueryDropdown(this.$dropdown, {
          data: this.getData.bind(this),
          selectable: true,
          filterable: true,
          filterRemote: true,
          multiSelect: this.$dropdown.hasClass('js-multiselect'),
          renderRow: this.renderRow.bind(this),
          toggleLabel: this.toggleLabel.bind(this),
          hidden() {
            if (onHide) {
              onHide();
            }
          },
    ```
7. 函数renderRow引用了deployKeyRowHtml函数：
    *gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#507*
    ```
    renderRow(item) {
        let criteria = {};
        let groupRowEl;
        switch (item.type) {
          case LEVEL_TYPES.DEPLOY_KEY:
            groupRowEl =
              this.accessLevel === ACCESS_LEVELS.PUSH ? this.deployKeyRowHtml(item, isActive) : '';
            break;
        }
        return groupRowEl;
      }
    ```
8. 用regex定位到缺陷函数，key.title没有过滤，直接嵌入html中，从这里开始沿着执行流向下分析（往上），从而定位该html如何渲染到html页面
    *gitlab/app/assets/javascripts/projects/settings/access_dropdown.js#534*
    ```
    deployKeyRowHtml(key, isActive) {
        return `
          <li>
            <a href="#" class="${isActiveClass}">
              <strong>${key.title}</strong>
            </a>
          </li>
        `;
      }
    ```
9. 从这里开始沿着执行流向上分析（往下），为了确定该片段会在网站的哪个页面和组件出现。 从上面分析可以看到 this.$dropdown被传进了gl_dropdown并且最终渲染了漏洞代码，因此从$dropdown出发，看看它在哪里被赋值：类AccessDropdown的构造函数中options解构获取了$dropdown标签，那么就需要查询该类在何处实例化，只能够全局搜索？搜索该文件名access_dropdown，（注意导入js文件时可以不带js后缀名）查看其导入位置，有两处。
    ![access_dropdown](/assets/gitlab/1/access_dropdown.png)

    分别是
    *gitlab/app/assets/javascripts/protected_branches/protected_branch_create.js*
    *gitlab/app/assets/javascripts/protected_branches/protected_branch_edit.js*
    首先分析第一个情况，可以看到$dropdown被赋值:
    *gitlab/app/assets/javascripts/protected_branches/protected_branch_create.js#71*
    ```
    buildDropdowns() {
        // Allowed to merge dropdown
        this[`${ACCESS_LEVELS.MERGE}_dropdown`] = new AccessDropdown({
          accessLevel: ACCESS_LEVELS.MERGE,
          accessLevelsData: gon.merge_access_levels,
          $dropdown: this.$allowedToMergeDropdown,
          onSelect: this.onSelectOption.bind(this),
          onHide: this.onDropdownHide.bind(this),
          hasLicense: this.hasLicense,
        });
        // Allowed to push dropdown
        this[`${ACCESS_LEVELS.PUSH}_dropdown`] = new AccessDropdown({
          accessLevel: ACCESS_LEVELS.PUSH,
          accessLevelsData: gon.push_access_levels,
          $dropdown: this.$allowedToPushDropdown,
          onSelect: this.onSelectOption.bind(this),
          onHide: this.onDropdownHide.bind(this),
          hasLicense: this.hasLicense,
        });
      }
    ```
10. 继续分析该文件，可以看到$dropdown被初始化位置，也就是说.js-allowed-to-merge和.js-allowed-to-push就是被挂载的类：
    *gitlab/app/assets/javascripts/protected_branches/protected_branch_create.js#15*
    ```
    constructor(options) {
        this.hasLicense = options.hasLicense;
        this.$wraps = {};
        this.hasChanges = false;
        this.$wrap = options.$wrap;
        this.$allowedToMergeDropdown = this.$wrap.find('.js-allowed-to-merge');
        this.$allowedToPushDropdown = this.$wrap.find('.js-allowed-to-push');
        this.$forcePushToggle = this.$wrap.find('.js-force-push-toggle');
        this.$codeOwnerToggle = this.$wrap.find('.js-code-owner-toggle');
        this.$wraps[ACCESS_LEVELS.MERGE] = this.$allowedToMergeDropdown.closest(
          `.${ACCESS_LEVELS.MERGE}-container`,
        );
        this.$wraps[ACCESS_LEVELS.PUSH] = this.$allowedToPushDropdown.closest(
          `.${ACCESS_LEVELS.PUSH}-container`,
        );
        this.buildDropdowns();
        this.bindEvents();
      }
    ```
11. 到此，被挂载的标签类已经确定，注意到rails一般是后端返回静态页面，而vue/js对静态页面的元素进行热更新，所以需要搜索rails的模板文件：
    ![js-allowed-to-push](/assets/gitlab/1/js-allowed-to-push.png)
    
    可以看到，有两个rails模板文件包含该class名，分别是：
    *gitlab/app/views/projects/protected_branches/_create_protected_branch.html.haml*
    *gitlab/app/views/shared/projects/protected_branches/_update_protected_branch.html.haml*
    先考虑第一种情况：
    找对应的controller：projects/protected_branches_controller.rb 调用该视图，说明该视图很可能是被其他controller调用：
    
    ![protected_branches_controller](/assets/gitlab/1/protected_branches_controller.png)

    分析视图名称，其中show是直接渲染的文件，而_index是局部渲染文件，用于被其他渲染文件调用，而show文件没有调用_index文件，_index文件调用了_create_protected_branch.html.haml，因此对该_index的调用进行分析。搜索: protected_branches/index，可以看到一处调用：*gitlab/app/views/projects/settings/repository/_protected_branches.html.haml*

    ![protected_branches1](/assets/gitlab/1/protected_branches1.png)

    ![protected_branches2](/assets/gitlab/1/protected_branches2.png)
    
12. 而projects/settings/repository_controller.rb调用了该show，自此，ui定位基本完成，只要访问projects/settings/repository路由即可。
    *gitlab/app/controllers/projects/settings/repository_controller.rb#63*
    ```
    def render_show
        define_variables
        render 'show'
    end
    ```

##### 基于数据流分析
1. 这一过程对什么数据会传输、存储和渲染进行分析，还是从初始点access_dropdown开始分析。
    ```
    deployKeyRowHtml(key, isActive) {
        return `
        <li>
            <a href="#" class="${isActiveClass}">
            <strong>${key.title}</strong>
            </a>
        </li>
        `;
    }
    ```
2. 经过分析得到，该数据最终来自
    *gitlab/app/assets/javascripts/projects/settings/api/access_dropdown_api.js#35*
    ```
    const DEPLOY_KEYS_PATH = '/-/autocomplete/deploy_keys_with_owners.json';
    export const getDeployKeys = (query) => {
    return axios.get(buildUrl(gon.relative_url_root || '', DEPLOY_KEYS_PATH), {
        params: {
        search: query,
        per_page: 20,
        active: true,
        project_id: gon.current_project_id,
        push_code: true,
        },
    });
    };
    ```
3. 获取后端的路由，找到对应后端，直接从数据库Deploykey中取出，并返回：
    *gitlab/app/controllers/autocomplete_controller.rb#55*
    ```
      def deploy_keys_with_owners
        deploy_keys = DeployKey.with_write_access_for_project(project)
        render json: DeployKeySerializer.new.represent(deploy_keys, { with_owner: true, user: current_user })
      end
    ```
    也就是说，漏洞UI渲染的是deploy_key数据，分析完毕。

#### Tips

* **前端到后端**
    
    一般前端负责对用户输入进行过滤，但是如果采用ruby的form_for方法渲染的静态页面，其中的action是固定的，而且也没有过滤操作。极其容易造成前端的数据没有过滤就给后端了。

* **后端到前端**
    
    数据是通过ruby的erb或者haml模型静态渲染，那么多半进行了过滤，因为这两个种模板默认对数据进行过滤。但是如果数据不是静态挂载，而是通过前端js获取，那么后端极有可能不会首先过滤，并且如果前端没有过滤，则xss出现。因此该xss出现在下拉菜单中就好说了，因为下拉菜单的数据往往是动态获取的，后端来静态渲染它们需要刷新页面。例如在同一个页面更新了数据，传入了后台。当显示的时候，我不可能刷新整个页面去显示那个数据，这时就需要通过api去拉取数据。

* **后端的过滤**
    
    后端的controller方法中，如果creat_params方法没有对数据进行过滤，那么后端很可能不会过滤。