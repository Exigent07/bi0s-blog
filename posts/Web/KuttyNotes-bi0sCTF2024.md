---
title: കുട്ടി Notes - bi0sCTF 2024
date: 2024-02-29 19:30:19
author: Lu513n
author_url: https://twitter.com/Lu513n
categories:
  - Web
tags:
  - bi0sCTF
  - XS-Leaks
  - DOM Clobbering
---

**tl;dr**

+ DOM Clobbering to Redirect to another page
+ Increasing Content using SQL Injection giving the same column multiple times
+ Connection-Pool XS-Leaks to measure the time for the page to load
+ Leak the flag character by character using the above techniques

<!--more-->

**Challenge Points**: 1000
**No. of solves**: 1
**Challenge Author**: [Lu513n](https://twitter.com/Lu513n)

## Challenge Description

I don't think you have enough time to solve this notes challenge too

> Please translate `കുട്ടി` in the title as `baby` as in `baby notes` and not `child` as the [google translate](https://translate.google.co.in/?sl=auto&tl=en&text=%E0%B4%95%E0%B5%81%E0%B4%9F%E0%B5%8D%E0%B4%9F%E0%B4%BF%20Notes&op=translate) suggests.

## Analysis

So Let's take a look at all the features of this app. We can add notes with a title and content.

![home](home.png)

All the notes can be listed at `/posts`.

![posts](posts.png)

A specific note can be visited using a `uuid` assigned to that note.

![post](post.png)

As we can see, the html is rendered there. So there is html injection where the posts are displayed. But there is no XSS as the page is protected by this [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) in the app

```js
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("hex");
  res.setHeader(
    "Content-Security-Policy",
    `
        default-src 'self';
        script-src 'nonce-${res.locals.nonce}' 'unsafe-inline';
        object-src 'none';
        base-uri 'none';
        connect-src 'self';
        navigate-to 'self';
    `
      .trim()
      .replace(/\s+/g, " ")
  );
});
```

We can also search for the notes using the `/search` endpoint where html injection is present.

![search](search.png)

We can report any note to the admin using the `/report` endpoint. We can only give the `uuid` of the note, so cannot make the admin visit an arbitrary page.

If we check the app source, we can also see that there is also `/delete`, `/all`, `/verify`, and `/:username/block` endpoints which are all accessible only by the admin.

`/delete` - Deletes a note
`/all` - returns all the notes and users as json
`/verify` - Verifies a user note
`/:username/block` - Deletes a user.

## Exploitation

The flag is in the admin's note, and the search function using `LIKE` points to an obvious [XS-Leak](https://xsleaks.dev/). But we need to find an oracle for the leak. Also, we need a way to make the admin visit our page as we can not execute js on the note site because of the **C**ontent **S**ecurity **P**olicy ([CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)).

### Redirecting the Admin

If we check the page admin visits to verify the note, we can see this HTML.

```html
        <script nonce="{{nonce}}">
            window.addEventListener('securitypolicyviolation', function(event) {
                document.location='about:blank';
            });
        </script>
    </head>
    <body>
        <h1 id="title">{{title}}</h1>
        <p id="content">{{{content}}}</p>
        Author : <p id="author">{{author}}</p>
        <script nonce="{{nonce}}" src="/js/verify.js"></script>
        <a href="/post/{{id}}">View Post</a>
        <script nonce="{{nonce}}">
            let id = "{{id}}";
            let user = "{{user}}";
            (async function() {
                for(let i = 0; i < rows.length; i++) {
                    if(rows[i].author.username == 'admin' || rows[i].author.username != user && rows[i].id == id) {
                        console.log("You can't Report Another user's post")
                        if(rows[i].author.username == 'admin'){
                            console.log("Blocking user for trying to Report admin's post")
                            document.location=`/${user}/block?block=true`;
                        }
                    }
```

#### Blocking JS files from loading

Here also html injection is present. Here the `rows` variable is coming from the `verify.js` and it can be invalidated if we can give another `script` in front of it. Then it will be invalidated because there is no nonce. If we manage to do that, we can make the value of rows, arbitrary using [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering). 

But the page also has a script that will redirect the page to `about:blank` if the [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) is violated. So to invalidate the `script` with triggering the [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) violation, we can use `<script type="text/plain">`

#### DOM clobbering

```html
<iframe name=rows srcdoc=" <iframe name=rows srcdoc=&quot; <a id='author' href='//admin:a@me.com'></a> &quot;></iframe> "></iframe>
```
![DOMClobber](DOMClobber.png)

This html would make the rows variable to an array with `rows[0].author.username` as `admin`.

#### Operator precedence

In the if condition `rows[i].author.username == 'admin' || rows[i].author.username != user && rows[i].id == id`, we don't need the check `rows[i].id == id` to be true as in JS `&&` has higher precedence than `||`. So the `&&` condition will be executed first. So we only need the first condition to be true.

![op](op.png)

Now, don't blame JS for this. Every programming language does this.

#### Render Blocking

If we try this payload, we will see that the admin is not redirecting. This is because, for [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) to work, it needs some time to load the html and execute the script only after that. For that, we can use some render blocking css. When we give `blocking=render` attribute to css, it will block the execution of scripts and other style elements until that resource is loaded.

```html
<link rel="stylesheet" blocking="render" href="/css/bootstrap.min.css">
<link rel="stylesheet" blocking="render" href="/css/bootstrap-icons.css">
<link rel="stylesheet" blocking="render" href="/css/home.css">
<link rel="stylesheet" blocking="render" href="/css/posts.css">
<link rel="stylesheet" blocking="render" href="/css/search.css">
```

Combining all these we can make a payload, which will redirect the admin to `/username/block` page. If we can start a user with `/` then we can redirect admin to any domain.

If that isn't enough, I forgot to check for the `uuid` format in the `/report` page 😎. So you can add an `&user` at the end of `uuid` and can give any value for `user` while reporting.

With this, we conclude that we can redirect the admin to any page we like. Now we need an [XS-Leak](https://xsleaks.dev/) oracle

### XS-Leak Oracle

#### Increasing content

If we check the `/search` page we can see that it also accepts a column name. So we can display whichever column we want of the note we searched.

```js
app.get("/search", loggedIn, async (req, res) => {
  if (!check(req.url.slice(req.url.indexOf("?") + 1))) {
    console.log("/search Error: Invalid search query");
    return res.json({ error: "Invalid search query" });
  }

  const query = req.query.q || "";
  const filter = req.query.f || "*";

  try {
    const posts = await Post.query()
      .column(filter)
      .where("title", "LIKE", `%${query}%`)
      .andWhere("author", req.session.username);

    return res.render("search", { posts: posts });
  } catch (err) {
    console.log("/search Error:", err);
    return res.json({ error: "Invalid search query" });
  }
});
```

Here we can see that the `filter` is used as the column name. So we can give the same column many times and increase the content of the page by a lot.

But if we just give `&f=content&f=content`, the page will not show the content two times, this is because the query returns an object and since the column name is the key, it will have the content only one time.

![s1](s1.png)

So to get it multiple times, we have to use aliases, for which we can use `f[a]=content&f[b]=content`. This will return content as `a` and `b` in the object.
doing this many times, we can increase the content of the page.

![s2](s2.png)

So depending on whether a note title matches the query or not, the page will have more or less content. So we can use this as an XS-Leak oracle.

#### Connection-Pool

Now that we have increased the content, we need a way to leak the increase in content. When the page has more content, the page will be loaded slower. But how do we time this? We can't directly get the time taken for a request as it is a different origin.

But Chrome has a limit of 256 sockets. So if we can block 255 sockets, then if we open this page in a new tab, and then send a request to a page where we can get the time, it only happens after the exploit page is loaded. Using this we can measure the time taken for the page to load.

To block 255 sockets, we can use a GO server which will run on 255 ports.

#### Unintended

During the CTF, [DrBrix](https://twitter.com/dr_brix) found an unintended solution. 

We can create a user for each hex character and their position in the flag. Then from the admin side, we can create a note for each character, and in their content, we can give `bi0sctf_{hexchar}<img loading="lazy" src="/{index}{hexchar}/block?block=true" />` and then proceed to search for each character from the admin side.

This way, when we search for a character, if the flag had that character, the flag note would be loaded, and because of the `lazy` attribute the request to `/block` won't be sent. But when the character is not in the flag, the note won't be loaded, and the request will be sent and that user will be deleted.

We can then check which users still exist and can get the flag.

## Putting it all together

So we can use the DOM Clobbering to redirect the admin to our page where we can measure the time taken for the page to load using connection-pool xsleaks. We can search for each character of the flag and measure the time taken for the page to load. If the time taken is more, then the character is in the flag, else not. Using this method, it would take a couple of reports to get the complete flag.

You can find the full exploit [here](https://gist.github.com/RohitNarayananM/e2aea9672ae5ab2724a4097b4c855872)

If this isn't detailed enough, message me on [twitter](https://twitter.com/Lu513n) or [discord](https://discordapp.com/users/766656046080327682).

**Flag**: `bi0sctf{f719b93ecd29}`

