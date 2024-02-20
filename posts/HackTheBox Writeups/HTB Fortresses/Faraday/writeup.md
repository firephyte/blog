# HTB Fortress Writeup: Faraday
## By: gnos1s

## Flag 1: Warmup

As usual, we start off with our Nmap scan:

```
# Nmap 7.92 scan initiated Mon Aug 14 22:00:04 2023 as: nmap -sC -sV -oA 10.13.37.14 10.13.37.14
Nmap scan report for 10.13.37.14
Host is up (0.58s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a8:05:53:ae:b1:8d:7e:90:f1:ea:81:6b:18:f6:5a:68 (RSA)
|   256 2e:7f:96:ec:c9:35:df:0a:cb:63:73:26:7c:15:9d:f5 (ECDSA)
|_  256 2f:ab:d4:f5:48:45:10:d2:3c:4e:55:ce:82:9e:22:3a (ED25519)
80/tcp   open  http            nginx 1.13.12
| http-git:
|   10.13.37.14:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Add app logic & requirements.txt
| http-title: Notifications
|_Requested resource was http://10.13.37.14/login?next=%2F
|_http-server-header: nginx/1.13.12
8888/tcp open  sun-answerbook?

<snip>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 14 22:03:05 2023 -- 1 IP address (1 host up) scanned in 181.17 seconds
```

We cab see three ports open. SSH on port 22, HTTP on port 80, and un unknown service on port 8888.

Let's first visit the webservice on port 80. The website requires login.



We can create an account and log in. We also saw from the Nmap scan that the website has an exposed Git repository. This means that we can probably get the source code. Let's dump the Git repository before we continue to enumerate the website:

```
$ git-dumper http://10.13.37.14/ 10.13.37.14-gitdump
```

Let's check out the website now. We are first redirected to a configuration page. 



It asked for a SMTP server and port, meaning the server is probably gonna send emails there. I'll just set that to my IP and port 25 without a username and password.
Next, we are redirected to /profile, where we are supposed to "select a name server":



I have no idea what that means, so I'll just select a random one. Next, we're redirected to /SendMessage, where we can send with a sender, message, and email.



This will probably send the email to my configuration (myself), so I'll just start a Python3 SMTP server:

```
$ sudo python3 -m smtpd -n -c DebuggingServer localhost:25
Password:
/usr/local/Cellar/python@3.11/3.11.4_1/Frameworks/Python.framework/Versions/3.11/lib/python3.11/smtpd.py:96: DeprecationWarning: The asyncore module is deprecated and will be removed in Python 3.12. The recommended replacement is asyncio
  import asyncore
/usr/local/Cellar/python@3.11/3.11.4_1/Frameworks/Python.framework/Versions/3.11/lib/python3.11/smtpd.py:97: DeprecationWarning: The asynchat module is deprecated and will be removed in Python 3.12. The recommended replacement is asyncio
  import asynchat

```

Now, I click "report" and we do get an email to our server. There's the first flag:

```
$ sudo python3 -m smtpd -n -c DebuggingServer 10.10.16.7:25
---------- MESSAGE FOLLOWS ----------
b'Subject: test'
b'X-Peer: 10.13.37.14'
b''
b'An event was reported at JohnConnor:'
b'test'
b'Here is your gift FARADAY{flag1}'
------------ END MESSAGE ------------
```

## Flag 2: Let's count



## Flag 3: Time to play



## Flag 4: Careful read



## Flag 5: Administrator Privesc



## Flag 6: Hidden pasta

Actually, for the past five flags I haven't talked about the service running on port 8888 at all. That's because it hasn't really been useful until now. When you connect using Netcat, the service requires your username and password:

```
$ nc 10.13.37.14 8888
Welcome to FaradaySEC stats!!!
Username:
```

And then once you log in using credentials from the webserver, the service returns the subject of your most recent message sent:

```
Password: gnos1s
access granted!!!
Hi gnos1s, this is your last subject:
test
```

When we dumped all of the password hashes from the SQLite database before, we mentioned that the pasta user's password was also crackable. The user's password is "antihacker". When we use those credentials on this service, we will get flag 6:

```
$ nc 10.13.37.14 8888
Welcome to FaradaySEC stats!!!
Username: pasta
Password: antihacker
access granted!!!
FARADAY{flag6}
```

## Flag 7: Root Kit