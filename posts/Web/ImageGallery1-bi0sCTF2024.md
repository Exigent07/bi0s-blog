---
title: Image Gallery - bi0sCTF 2024 
date: 2024-03-06 20:01:14
author: ma1f0y
author_url: https://twitter.com/mal_f0y
categories:
  - Web
tags:
  - bi0sCTF2024
---

**tl;dr**

 Image gallery 1

+ Get xss by uploading index.html in public dir
+ Use bf cache to get the flag.

Image gallery 2
+ Slice files.js using nginx partial caching.
+ Use Subresource Integrity to load the right script
+ Use DOM clobbering and Cache probing to leak the flag uuid

<!--more-->

## Intro

I made two interesting Web challenges for bi0sCTF 2024, Image gallery 1 & 2. Solution for both of the challenges ~~ab~~uses interesting behaviors of both browser and server which I'm going to cover in this blog.

## Image gallery 1

**Challenge Points**: 752
**No. of solves**:  22
**[Source](https://github.com/ma1f0y/ctf-challenges/tree/master/bi0sctf-2024/Image_galler_1)**
### Description
Image gallery service provides you the best solution to store your precious images. Do not forget to share your images with admin.

### Analysis
The challenge provides us with an interface to upload and view images. If we check the source code, we have an express application with only 3 endpoints.

`/`: generates a random uuid and creates a folder with that name in the public directory and sets that as sid cookie value. And it also renders the template with the list of files in that particular folder if you are sending a request with that cookie.

`/upload`: Upload files to the directory taken from the cookie value.

`/share`: We can share images with the admin, and the admin bot will visit the image.
All the files are uploaded to the public directory so anyone can view anyone's file if they know the random uuid of another person.
There is also a plantflag function that also creates a random uuid folder in the public dir and puts the flag.txt in that. The same uuid is used in the adminbot's cookie to visit our image. So to get the flag we must get that uuid. let's see how we can do that.

### Solution
If you check the code for file upload you can notice something wrong.
```javascript=
if (!req.files || !req.cookies.sid) {
    return res.status(400).send('Invalid request');
  }
const uploadedFile = req.files.image;
.....
await uploadedFile.mv(`./public/${req.cookies.sid}/${uploadedFile.name}`);

```
Without any proper validation the cookie from the request is directly appended to the saving file path. So we can use path traversal attack to upload files to any directory we want.

But how will we get the flag using this?
There is a proper regex check in the cookie while reading files using our cookie. So we cannot read files from other folders.

```javascript=
if(req.cookies.sid && /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(req.cookies.sid))
```

The flag_id is there on the adminbot, can we try getting XSS on admin bot? We can upload html files but if you check the bot.js you can see that adminbot only visit ``http://localhost:3000/?f=${id}`` endpoint to view our image. 

So even if we upload a html file we won't be able to load it in the adminbot. But wait there is an interesting catch here. If you notice the application source code we can see that it use express static to server files from the public dir.
```javascript=
app.use(express.static('public'));
```
And express.static(I think most of the static file servers) will server index.html from the root folder(which is `public` in this case) of the server while visiting the `/` endpoint of the website.

So if we upload an index.html to the `public` directory with our xss payload, we can get xss in the adminbot. The next question will be how will we get the flag_id, because the cookie httpOnly, so we cannot get the flag_id from the cookie. So we need to find another way to get the flag.
The `/` endpoint's response has the flag_id in it, but to get xss we have to change the response of `/` endpoint.

If we check the bot.js, we can see that the bot first visits the challenge site once and then loads our image.
```javascript=
await page.goto(`http://localhost:3000/`);
await new Promise((resolve) => setTimeout(resolve, 3000));
await page.goto(
      `http://localhost:3000/?f=${id}`,
      { timeout: 5000 }
    );
```
We can use the help of browser's [bf cache](https://web.dev/articles/bfcache) to solve the challenge. We will upload the index.html after the first visit and then when the bot visits the second time our XSS payload gets executed, and we can use history.back() to get the cached page with the flag_id.

Final [exploit](https://gist.github.com/ma1f0y/966c907229cbbf7069ed15bb44ec1ff1)


## Image gallery 2

**Challenge Points**: 1000
**No. of solves**: 0
**[Source](https://github.com/ma1f0y/ctf-challenges/tree/master/bi0sctf-2024/Image_galler_2)**

### Description
This time we have built a more secure version. Pls don't hack
use:
chrome://flags/#unsafely-treat-insecure-origin-as-secure
and add the challenge host.

### Analysis

Although it's named as the second version, this challenge is completely unrelated to the first one. The only thing similar is the interface where we can upload and view images.

We can start by analyzing the source code. In the docker-compose.yml we can see that we have 3 services.

- app: The backend of the application, it is a simple go web app.
- nginx: used for proxying and caching the requests and responses.
- bot: adminbot for the challenge(this was given for the participants to test their exploit. The bot was isolated from the challenge network when it was hosted.)

We'll go through each service in detail.

This time we have a go application as the backend. Where we can upload, view, and delete files. Everyone visiting the site will get a random uuid folder where the files will be uploaded and that uuid will be set as the cookie `sid`.

This time we don't have path traversal in fileupload, So we can only upload files to our folder. And for viewing the files, there is one extra file called `files.js` in each folder. This js file contains the name(uuid) of the folder and a list of names of all the files in that particular folder. This js file is served in the `/files.js` endpoint based on the cookie from the requests and is updated after every file upload. This js file is included along with `main.js` in the index page to view the list of images. We cannot upload a file, whose name ends with `.js` which prevents us from overwriting `files.js`.

In the nginx service we can see that a proper CSP header is added for every request, where we can only load two script(`main.js` and `files.js`) from the challenge origin and bootstrap.min.js and only loads the styles from `/style.css` and bootstrap css 
```nginx=
location /static/ {
            deny all;
        }
        location ~ \.(jpg|jpeg|png|svg|mp4|css|js)$ {
            
            if ($cookie_sid !~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") { return 403; }
            proxy_cache mycache;
            slice              4096; 
            proxy_cache_key    $host$uri$is_args$args$slice_range$cookie_sid;
            proxy_cache_bypass $cookie_nocache $arg_nocache;
            proxy_set_header   Range $slice_range;
            proxy_http_version 1.1;
            proxy_cache_valid  200 206 1h;
            proxy_pass http://app:3000;
        }

        proxy_pass http://app:3000;
        add_header Content-Security-Policy "default-src 'self';style-src https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css $app_host/style.css;  script-src $app_host/files.js $app_host/main.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js;";
```
And a [Byte-Range Caching](https://www.nginx.com/blog/smart-efficient-byte-range-caching-nginx/) is also implemented for most of the static files. All the uploaded static files are served with `/static` prefixed url, but directory listing is prevented by `deny all` directive.

Next, we can check the adminbot. The bot accepts a url from the user. It checks if url starts with the challenge site, and then it loads the main page and upload flag.png to its folder and then it will visit our url.

So our goal is to get the flag from the adminbot. Okay now let's exploit the challenge.

### Solution

XSS? Is it possible?..

I don't think so, because of the CSP, the only allowed js are:
`main.js` which is static.
`files.js` base64 of our filenames, makes it harder rather impossible to get xss.
`https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js` Well good luck finding xss there.

To get the flag we need to know the uuid of the folder in which the flag is uploaded. Let's check where we can find it. 

It will be set as the cookie on the bot, But sadly it is httpOnly and there is no way to leak the cookie. 

The next thing we can notice is that `files.js` which is the important part of this challenge, also has the uuid in it as `id` variable

```go
content := fmt.Sprintf("if(top.location.origin==='%s')\nfileNames = JSON.parse(atob(decodeURIComponent('%s'))),\nid = '%s';", apphost ,uencoded, sid)
fname := filepath.Join(dirPath,"files.js")
file, err := os.Create(fname)
...
file.WriteString(content)
```
We can try loading the js file on our site and get the id?
Nope! there are two things that are preventing this from happening.
* `top.location.origin` should be the challenge site, but due to the CSP there is no way to frame any other site in the challenge site.
* While serving the files.js the server also sets a CORP header to same-origin

```go
w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
```
I'll try to break down the intended solution for the challenge into different parts.

#### SVG helps
The cookie is Samesite `None` which means we can easily do CSRF and upload files on the bot side. But to do that the bot has to visit our site. Currently, we can only give the challenge site as input to the bot and we don't have any XSS in the challenge site. Can we redirect the admin bot to our site? If we had html injection we could easily redirect the admin bot to our site using meta tag. But sadly `.html` is not allowed in the static file extensions in nginx config and `/` -> `index.html`  will also be blocked by the nginx rule.

Luckily we have svg allowed in the list and if you guys didn't know we can include html inside SVG files

So simply we can include html meta tag inside svg to redirect adminbot to our site

```svg=
<svg xmlns:html="http://www.w3.org/1999/xhtml" >
<html:meta http-equiv="refresh" content="0; url=http://webhook.site"></html:meta>
</svg>
```
For the further exploitation of the challenge, we'll be using svg to load html if needed.

#### Nginx caching tragedy

If you were thinking that we can cache the js file and retrieve the content(Cache Deception), it won't work here because the cache key also includes the cookie :Sadge:
Unless we don't have the cookie that is used for caching, we won't get the cached response.

But we can make something useful with the caching. The byte range caching implementation has a big problem, you can slice the content of files by caching it by parts.

This part of the challenge was inspired by [ACSC 2023 Gotion Challenge](https://blog.tyage.net/posts/2023-03-12-acsc-2023-gotion/)

In the above-mentioned challenge, we can see how to get xss using byte range caching. But here that is not possible because we don't have total control over the content inside the js file as our input(the name of files that we upload) will be base64 and url encoded before it is written to the js file. 

```go
var fileNames []string
for _, file := range files {
	if file.Name() != "files.js" {
		fileNames = append(fileNames, file.Name())
	}
}
jsonData, err := json.Marshal(fileNames)
...
base64Data := base64.StdEncoding.EncodeToString(jsonData)
uencoded := url.QueryEscape(base64Data)
content := fmt.Sprintf("if(top.location.origin==='%s')\nfileNames = JSON.parse(atob(decodeURIComponent('%s'))),\nid = '%s';", apphost ,uencoded, sid)
```
But what we have control over is the size of the content. We can increase the size of the file by uploading files with large names. Then we can make the nginx cache the first 4096 bytes in such a way that `\nid = '` in the js file will be the ending bytes.

Then we can reduce the size of the js file(by deleting files) to make the first few bytes of the 2nd byte range(4096-8191) as the last two chars of the uuid.

For example, if files.js is like:

``
if(top.location.origin==='web2.bi0s.in')\nfileNames = JSON.parse(atob(decodeURIComponent('...'))),\nid = '2ae7787b-7a17-4742-84dd-53b10365ff5b';
``

while caching first byte Range files.js[0-4095]
``if(top.location.origin==='web2.bi0s.in')\nfileNames = JSON.parse(atob(decodeURIComponent('........'))),\nid = '``

and while caching the second range
files.js[4096-4099]
``5b';``

After that, when we send a normal request to the files.js without any Range header the nginx will concat the caches and give the response. 

``if(top.location.origin==='web2.bi0s.in')\nfileNames = JSON.parse(atob(decodeURIComponent('........'))),\nid = '5b';....``

**Note** _because of the base64 we will not be able to cache it as a single character._

We can do the caching from the client side because the cookie is `Samesite:None` and we can use `Range` header in [cors fetch](https://fetch.spec.whatwg.org/#cors-safelisted-request-header)


Now we can make the nginx to cache sliced id of length 2,4,6 etc. The next part is to leak the id.

#### Subresource Integrity(SRI)

Now we have cached the files.js in such a way that only two characters in the file are unknown to us. What we can do is we can use SRI to find those chars. We'll generate all the hashes with the possible two-character combinations. Then we'll add hash to the `integrity` attribute and try to load the `files.js` in a script tag(which is allowed in CSP).
When the given hash matches the hash of the content of the file it will load the script otherwise it won't. This can be done only on the challenge site, because CORS will block loading scripts from cross-origin with integrity. So the next question will be, how will we know if a particular script is loaded or not in the challenge site from our site?

This is the most interesting part, which I liked the most about the challenge.

#### DOM clobbering to Cache probing

The challenge uses two script files `files.js` and `main.js`. In main.js, it expects `fileNames` and `id` variables from the files.js and then it will create images using the id and each filename. 
```javascript=
if(fileNames){
    for(i=0;i<fileNames.length;i++){
          fileName = fileNames[i]
          const imgElement = document.createElement('img');
          imgElement.src = `/static/${id}/${fileName}`;

          imgElement.alt = `Image: ${fileName}`;

          galleryDiv.appendChild(imgElement);
    }

} 
```
But what if `files.js` is not loaded. `fileNames` and `id` variables won't be defined. As most of the client-side people might know we can define these variables using DOM Clobbering!!. So we can load the image we want by clobbering those variables.

So the idea is that we will try to load the cached `files.js` with the integrity attribute containing the hash we want to check along with `main.js` and DOM clobbering payload. If the `files.js` is loaded our DOM clobbering will not work and our image will not be loaded, otherwise our image will load.

```html
<script integrity="sha256-{b}" src="/files.js?{key}"></script>
<a id="id" href="abc:asdf">asdff</a>
<a id="fileNames" href="asd:asdf/../../../../../static/{image}?{cha}">fasd</a>
<a id="fileNames" href="asd:asdf">fwe</a>
<div class="gallery row">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script> 
<script src="/main.js"></script>
```

Then we just have to check if our image loaded or not from our site to know whether the script was loaded or not. This is possible using [cache probing](https://xsleaks.dev/docs/attacks/cache-probing/) attack. If our image is loaded then it will be cached in the browser, when we request the same image from our site it will fetch that image from the cache, if it was not cached it will send request to the server and get the image. Fetching an image from the browser cache will take less time compared to fetching it from the server, now we can use this oracle to know whether our image is loaded or not. Here I used `image.complete` property to check whether the image is loaded or not after a particular amount of time.

```javascript=
async function load_and_check(url){
        var img = new Image();
        img.src = url;
        await new Promise(r=>setTimeout(r,20));
        return img.complete;
}
```

**Note:** _This technique will only work in headless chrome. Proper [cache-partitioning](https://developer.chrome.com/blog/http-cache-partitioning) has been implemented in normal browsers to prevent these types of attacks._

#### Exploiittt

Now we have all the parts we can build our exploit.
First, we send our svg to redirect adminbot to our site.

Then we will upload files to the bot's folder for increasing the size of the files.js. Then we have to cache the first byte range[0-4096] when last bytes are `id = '`. Here we can use a couple of base64 and urlencoding tricks to get the bytes perfectly aligned as we want.

Next, we have to cache the 2nd byte range to get part of the id. We can upload and delete files to align the bytes. We have to store each combinations with different cache keys, for example: 
key 1 will have `id = '5b';` in the files.js, key 2 will have `id = 'ff5b';` and so on.

Finally upload a file with large filename. This is done because when we cache the first byte range the response will be having Content-Range header which has the total size of the file. After that when we are using that cache nginx will try to fetch that much content from the backend. So to compensate that we are uploading one more file after we cache everything.

The next step is to leak the cached id using SRI,DOM clobbering and cache probing

For a single cache there will be 256 combinations that we have to check and there will be 18 such caches. We can use iframe for each and split the 256 into different parts to make the exploitation faster.

From our server, we can dynamically generate the svg containg iframes with the payload(SRI+DOMclobbering) and upload it. From the client side we fetch url for that svg and open it in a new window. Then we will check which image is not cached. Based on that we can leak the chars. we can repeat the process until we get the complete id. 

After you leak the id you can get the flag by visiting `/static/{id}/flag.png`.

Final [exploit](https://gist.github.com/ma1f0y/4bf564310e8d205eb6d52d1cb0df0bea)
I would like to mention my teammate [Lu513n](https://twitter.com/Lu513n/) for helping me to craft this beautiful exploit.


## Closing thoughts

Hope everyone enjoyed the challenges. Sad that no one solved Image Gallery 2. I know it's a pretty time-consuming challenge. But I learned a ton of stuff and it was really fun making these challenges. Hope you guys also got something interesting from this writeup :)




