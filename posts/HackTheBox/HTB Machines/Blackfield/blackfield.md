# HTB Machine Writeup: Blackfield
### By: gnos1s

## Machine Difficulty: Hard

## Operating System: Windows

## Introduction

Blackfield was a solid Active Directory box. It starts off with enumerating an SMB share to get a list of users, then using that list to find active users. One of those users has Kerberos Pre-authentication disabled, which allows for an AS-REP roasting attack to get that user's hash. This hash can then be cracked offline using Hashcat. Using this user's credentials, we can reset another user's password, and use that new user's password to get access to a new SMB share. In this share, we can then find a lsass.dmp file that allows us to dump credentials from memory using PyPykatz and extract another user's password hash. We can authenticate to WinRM using this hash and get a shell with the user flag. Lastly, we abuse this user's SeBackupPrivilege to create a backup of the NTDS.dit and shadow.bak files, allowing us to extract the administrator's password hash and getting a shell as Administrator.
## Enumeration

As usual, we start off with our Nmap scan:

```
$ nmap -sC -sV -oA nmap/blackfield 10.10.10.192
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-09 21:19:16 HKT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.25 seconds
```

The host seems to be down? But we can ping it. Let's try -Pn:

```
$ nmap -sC -sV -oA nmap/blackfield -Pn 10.10.10.192
# Nmap 7.92 scan initiated Tue Jan  9 21:19:33 2024 as: nmap -sC -sV -oA nmap/blackfield -Pn 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.088s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-09 20:23:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-01-09T20:23:49
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  9 21:24:27 2024 -- 1 IP address (1 host up) scanned in 293.94 seconds
```

We can see many open WIndows ports; this seems to be an AD box. Let's try SMB null authentication first.

```
$ smbclient -N -L //10.10.10.192

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	profiles$       Disk
	SYSVOL          Disk      Logon server share
```

We can see a non-default shared called profiles$. Let's go in and take a look:

```
$ smbclient -N \\\\10.10.10.192\\profiles$
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun  4 00:47:12 2020
  ..                                  D        0  Thu Jun  4 00:47:12 2020
  AAlleni                             D        0  Thu Jun  4 00:47:11 2020
  ABarteski                           D        0  Thu Jun  4 00:47:11 2020
  ABekesz                             D        0  Thu Jun  4 00:47:11 2020
  ABenzies                            D        0  Thu Jun  4 00:47:11 2020
  ABiemiller                          D        0  Thu Jun  4 00:47:11 2020
  AChampken                           D        0  Thu Jun  4 00:47:11 2020
  ACheretei                           D        0  Thu Jun  4 00:47:11 2020
  ACsonaki                            D        0  Thu Jun  4 00:47:11 2020
  AHigchens                           D        0  Thu Jun  4 00:47:11 2020
  AJaquemai                           D        0  Thu Jun  4 00:47:11 2020
  AKlado                              D        0  Thu Jun  4 00:47:11 2020
  AKoffenburger                       D        0  Thu Jun  4 00:47:11 2020
  AKollolli                           D        0  Thu Jun  4 00:47:11 2020
  AKruppe                             D        0  Thu Jun  4 00:47:11 2020
  AKubale                             D        0  Thu Jun  4 00:47:11 2020
  ALamerz                             D        0  Thu Jun  4 00:47:11 2020
  AMaceldon                           D        0  Thu Jun  4 00:47:11 2020
  AMasalunga                          D        0  Thu Jun  4 00:47:11 2020
  ANavay                              D        0  Thu Jun  4 00:47:11 2020
  ANesterova                          D        0  Thu Jun  4 00:47:11 2020
  ANeusse                             D        0  Thu Jun  4 00:47:11 2020
  AOkleshen                           D        0  Thu Jun  4 00:47:11 2020
  APustulka                           D        0  Thu Jun  4 00:47:11 2020
  ARotella                            D        0  Thu Jun  4 00:47:11 2020
  ASanwardeker                        D        0  Thu Jun  4 00:47:11 2020
  AShadaia                            D        0  Thu Jun  4 00:47:11 2020
  ASischo                             D        0  Thu Jun  4 00:47:11 2020
  ASpruce                             D        0  Thu Jun  4 00:47:11 2020
  ATakach                             D        0  Thu Jun  4 00:47:11 2020
  
  <snip>
  
  YSeturino                           D        0  Thu Jun  4 00:47:12 2020
  YSkoropada                          D        0  Thu Jun  4 00:47:12 2020
  YVonebers                           D        0  Thu Jun  4 00:47:12 2020
  YZarpentine                         D        0  Thu Jun  4 00:47:12 2020
  ZAlatti                             D        0  Thu Jun  4 00:47:12 2020
  ZKrenselewski                       D        0  Thu Jun  4 00:47:12 2020
  ZMalaab                             D        0  Thu Jun  4 00:47:12 2020
  ZMiick                              D        0  Thu Jun  4 00:47:12 2020
  ZScozzari                           D        0  Thu Jun  4 00:47:12 2020
  ZTimofeeff                          D        0  Thu Jun  4 00:47:12 2020
  ZWausik                             D        0  Thu Jun  4 00:47:12 2020

		5102079 blocks of size 4096. 1692377 blocks available
```

I tried checking into some of those directories but there wasn't anything. This just looks like a big list of users. Maybe we should try user enumeration?

CME doesn't work because SMB allows anonymous authentication, so I used Kerbrute instead:

