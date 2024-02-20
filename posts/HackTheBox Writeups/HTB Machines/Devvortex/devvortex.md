# HTB Machine Writeup: Devvortex
### By: gnos1s

### Machine Difficulty: Easy
### Machine Release Date: 25 Nov 2023
### Operating System: Linux

## Foothold

As usual, we start off with our Nmap scan:

```
$ nmap -sC -sV -oA nmap/devvortex 10.10.11.242
Nmap scan report for 10.10.11.242
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 26 08:29:16 2023 -- 1 IP address (1 host up) scanned in 27.63 seconds
```

We can see a webserver running on port 80, redirecting us to devvortex.htb. Let's add that to our hosts file:

```
$ echo "10.10.11.242 devvortex.htb" >> /etc/hosts
```

We can now view the page. It appears to be a static HTML site:

![home](posts/HTB%20Machines/Keeper/assets/home.png)

We can try doing a vhost scan to find subdomains. We do find one domain, dev.devvortex.htb:

```
$ ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.devvortex.htb' -u http://devvortex.htb/ -fs 154


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /Users/ethanwang/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

[Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 1644ms]
    * FUZZ: dev

:: Progress: [4989/4989] :: Job [1/1] :: 675 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

Visiting the site, it appears to be running Joomla. 