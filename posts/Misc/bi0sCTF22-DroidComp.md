---
title: DroidComp - bi0sCTF 2022
date: 2023-01-25 09:41:03
author: komi
author_url: https://twitter.com/r_srikesh
categories:
  - Misc
tags:
  - bi0sCTF-2022
  - Android 
---

**tl;dr**

+ Exploit Android Webview Javascript Interface 
+ Communicate with a Service via AIDL 

<!--more-->

**Challenge Points**: 964
**No. of solves**: 10
**Challenge Author**: [komi](https://twitter.com/r_srikesh)

## Challenge Description & Handout

`Here is the APK file. Get the flag by exploiting the vulnerabilities.`

Handout consists of an APK file.

## Initial Analysis

![manifest.xml](1.png)

The apk consists of 2 activities and a service. Activity **m** is the main activity and **a** is the webview activity. The service defined here is **IService** .

## Vulnerability & Exploitation - Webview

When we look at the settings of the webview , we could see couple of settings which could be exploited. 

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new c(this), "client");
webView.getSettings().getAllowUniversalAccessFromFileURLs();
```

These settings could mean: 

+ Javascript code can be executed in the webview
+ Object of class **c** can be accessed from the javascript code and the object   of class **c** can access the methods of the class **c**.
+ Allow Universal Access from File URLS. 

Looking at the code of class **c**:

```java
public class c {
    public c(a aVar) {
    }

    @JavascriptInterface
    public String d() {
        return new h().s(BuildConfig.APPLICATION_ID);
    }
}
```

Since function **d** is annotated with **@JavascriptInterface** , it could be accessed from the javascript code. 

Now, lets device our exploit strategy to get the flag.

+ Create a html file to call the function **d** from the javascript code. 
+ Push the html file into the device to get its location.
+ Call the activity with appropriate intent and pass the location of the html file as an extra. 

Here is the [link](https://github.com/rSrikesh/bi0sCTF-2022/blob/main/Exploits/pwned.html) to the html file.

Push this html file into our device using adb and call the webview activity via the command

```bash
adb shell am start -a "android.intent.action.CUSTOM_INTENT" -n "x.y.z/.a" -d "bi0s://android/?web=file:///sdcard/pwned.html"
```

et voila! We got the first half of the flag.

![flag](2.png)

## Vulnerability & Exploitation - Services & AIDL

Now, we have to get the second half of the flag. Lets look at the code of the service **IService**. 

```java
public class IService extends Service {
    private IClass iclass = new IClass();

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.iclass;
    }
}
```

The service is bound to the class **IClass**. Looking at the code of IClass.java

```java
public class IClass extends aidlInterface.Stub {
    @Override // r.s.aidlInterface.Stub, android.os.IInterface
    public IBinder asBinder() {
        return this;
    }

    @Override // r.s.aidlInterface
    public String z() throws RemoteException {
        return new h().ss(BuildConfig.APPLICATION_ID);
    }
}
```

We could see that the function **z** is returning a string which could most likely the second part of the flag.

Now, our strategy is create an exploit app which binds to the service **IService** and calls the function **z**. 

Here is the [link](https://github.com/rSrikesh/bi0sCTF-2022/tree/main/Exploits/Exploit) to the exploit app.

On running the exploit app, we get the second half of the flag.

![flag](3.png)

## Conclusion

This was the first time I created a challenge for a CTF. I had a lot of fun creating this challenge.

Flag: `bi0sCTF{4ndr01d_15_50_vuln3r4bl3}`









