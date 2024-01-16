---
{"dg-publish":true,"permalink":"/machines/presidential-1-writeup/","noteIcon":""}
---


## Presidential 1



┌──(root㉿kali)-[/home/kali/Documents]
└─# nmap -sS -sC --min-rate=5000 -Pn -n -vvv -p- 192.168.0.108 -vvv
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-16 05:13 EST


Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  REASON
80/tcp   open  http     syn-ack ttl 64
|_http-title: Ontario Election Services &raquo; Vote Now!
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
2082/tcp open  infowave syn-ack ttl 64
MAC Address: 00:0C:29:82:79:56 (VMware)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 05:13
Completed NSE at 05:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 05:13
Completed NSE at 05:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.54 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)




--------

─(root㉿kali)-[/home/kali/Documents]
└─# whatweb 192.168.0.108
http://192.168.0.108 [200 OK] Apache[2.4.6], Bootstrap, Country[RESERVED][ZZ], Email[contact@example.com,contact@votenow.loca], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.5.38], IP[192.168.0.108], JQuery, PHP[5.5.38], Script, Title[Ontario Election Services &raquo; Vote Now!]


apache

![Pasted image 20240116041515.png](/img/user/Pasted%20image%2020240116041515.png)








![Pasted image 20240116045234.png](/img/user/Pasted%20image%2020240116045234.png)



┌──(root㉿kali)-[/home/kali/Documents]
└─# gobuster  vhost  -u http://votenow.local/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  --append-domain   -t1 | grep -v 400
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://votenow.local/
[+] Method:          GET
[+] Threads:         1
[+] Wordlist:        /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: datasafe.votenow.local Status: 200 [Size: 9499]
Progress: 11322 / 220561 (5.13%)^C




┌──(root㉿kali)-[/home/kali/Documents]
└─# gobuster  dir  -u 192.168.0.108 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,php.bak,bak,tar
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.108
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,php.bak,bak,tar
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 236] [--> http://192.168.0.108/assets/]
/config.php.bak       (Status: 200) [Size: 107]
/config.php           (Status: 200) [Size: 0]
