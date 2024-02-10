# HTB Machine Writeup: CozyHosting
### By: gnos1s

### Machine Difficulty: Easy
### Machine Release Date: 2 September 2023
### Operating System: Linux

## Enumeration

As usual, we start off with our Nmap scan:

```
$ cat nmap.nmap
# Nmap 7.92 scan initiated Sun Sep  3 15:01:06 2023 as: nmap -sC -sV -oA nmap 10.10.11.230
Nmap scan report for 10.10.11.230
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep  3 15:03:04 2023 -- 1 IP address (1 host up) scanned in 117.40 seconds
```

Only ports 22 and 80 are open. I'm gonna visit Port 80 to see what's going on there.

I need to add cozyhosting.htb to my host file:

```
echo "10.10.11.230 cozyhosting.htb >> /etc/hosts"
```

![homepage](homepage.png)

It seems to be a static site, nothing interesting on the page or in the source code. The only interesting thing is a login page. Let's go check it out.

![login](posts/HTB%20Machines/CozyHosting/assets/login.png)

I did a lot of searching around on this login page, but didn't find login bypasses, credentials, or anything. I'm going to run a directory fuzz:

```
$ gobuster dir -w ~/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://cozyhosting.htb/
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /Users/ethanwang/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/14 14:14:02 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/login                (Status: 200) [Size: 4431]
/index                (Status: 200) [Size: 12706]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]
/.                    (Status: 200) [Size: 0]
```

The scan did find /admin, but that just redirects back to login. One interesting thing is the /error though. WHen I visit it, I get this weird error page:

![error](error.png)

When I google this weird "Whitelabel Error Page", it reveals that the website is running Spring Boot. Spring Boot always means a good chance at Spring Boot Actuator, which is at /actuator. I'm going to see if that exists, and it does!

![actuator](actuator.png)

There is actually another way you could have found this directory. Some wordlists do have actuator in them. Raft-wmall-words, the one I'm using, doesn't. But Raft-medium-words does contain the word actuator. This really shows the importance of fuzzing with multiple wordlists. You risk missing out on really important stuff in the recon stage.

Anyways, at this /actuator endpoint, there is a directory /actuator/sessions that includes another user's session!

![sessions](sessions.png)

I can replace my JSESSIONID cookie with kanderson's cookie:

![cookie](assets/cookie.png)

And I can now access the admin panel! There is only one real piece of functionality on the admin panel, 