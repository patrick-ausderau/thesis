 <!--
 /**********************************************************
 * Web Cryptography API EBook
 * Copyright (c) 2014 Patrick Ausderau
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **********************************************************/
 -->
 <!doctype html>
<html>
<head>
<title>Encrypt and Decrypt</title>
<meta charset="utf-8">
<script src="polycrypt/common/util.js"></script>
<script src="polycrypt/front/polycrypt.js"></script>
</head>
<body>
<h1>Test Web Cryptographic API - PHP Encrypt and JavaScript Decrypt Message</h1>

<p id="logMsg">The message is encrypted on server side with PHP.<br>The key has been converted to PEM format from <a href="http://www.php.net/manual/en/function.openssl-pkey-get-public.php#104439" target="_blank">ppostma1</a> hack.<br></p>


<?php
	$pub_key = $_POST["public_key"];
	if($pub_key){
		?>
		<h2>1. Message has been encrypted with your public key</h2>
		<p>If done properly, you are the only one who can decrypt this message.</p>
		<pre><?php
		$key_elem = json_decode($pub_key, true);
		var_dump($key_elem);
		//Ugly hack to transform the public key to PEM format because it works only with a 2048 bits key
		//from http://fi1.php.net/manual/en/function.openssl-pkey-get-public.php#104439
		$prepa = wordwrap('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'.'MIIBCgKCAQEA'.str_replace(array("_", "-", "="), array("/", "+", ""), $key_elem["n"]).'ID'.$key_elem["e"], 64, "\r\n", true);
		$key = <<<EOF
-----BEGIN PUBLIC KEY-----
$prepa
-----END PUBLIC KEY-----
EOF;
		$res = openssl_pkey_get_public($key);
		print_r(openssl_pkey_get_details($res)); 
		echo "\n";
		//content to be encrypted is in a file outside the www folder.
		//the epub file has been "unzipped" and the next/previous content is known from its package.opf configuration file 
		$list_of_content = array();
		$current_file = $_POST["current_file"];
		if(!$current_file)
			$current_file = 0;
		if($_POST["next"])
			$current_file++;
		elseif($_POST["prev"])
			$current_file--;
		$prev_file = true;
		$next_file = true;
		$tmp;
		foreach(file("../../secret/moby-dick/OPS/package.opf") as $line){
			
			if(strpos($line, '<item id="') !== false && strpos($line, '.xhtml') !== false ){
				$tmp = substr($line, strpos($line, 'href="') + strlen('href="'), strpos($line, '.xhtml') + strlen('.xhtml') - (strpos($line, 'href="') + strlen('href="')));
				//normal files (preface, chapters,...)
				if(strpos($line, '<item id="x') !== false)
					array_push($list_of_content, $tmp);
				//"special" files (cover, title,...)
				elseif(strpos($line, '<item id="cover"') !== false)
					$list_of_content[0] = $tmp;
				elseif(strpos($line, '<item id="titlepage"') !== false)
					$list_of_content[1] = $tmp;
				elseif(strpos($line, '<item id="copyright"') !== false)
					$list_of_content[2] = $tmp;
			}
		}
		if($current_file <= 0)
			$prev_file = false;
		elseif($current_file >= count($list_of_content) - 1)
			$next_file = false;

		$write_file = "moby-dick/OPS/".$list_of_content[$current_file];
		$resfile = fopen($write_file, "w");
		//smart quotes don't get encrypted nicely :(
		//$search = array(chr(145), chr(146), chr(147), chr(148), chr(151)); 
		//$replace = array("'", "'", '"', '"', '-'); 
		//123 * 16 = 1968bits = max to encode with a 2048 key
		foreach(str_split(file_get_contents("../../secret/moby-dick/OPS/".$list_of_content[$current_file]),123) as $val){
			//the quote and other special char don't get encrypted very friendly
			//$val = str_replace($search, $replace, $val);
			openssl_public_encrypt($val, $encrypted, $res);
			fwrite($resfile, base64_encode($encrypted));
		}
		fclose($resfile);
		echo "</pre>";
		echo "Encrypted file: <a href=\"$write_file\" target=\"_blank\">$write_file</a>";
		?>
		<form>
		   file content:<br>
			<textarea id="encrypted" name="encrypted" readonly rows="14" cols="80"><?php
				echo file_get_contents($write_file);
			?></textarea><br>
			<button id="decrypt" type="button">Decrypt</button>&nbsp;<span id="time_warn" style="color:orange;"></span>
		</form>

		<h2>2. Your file get decrypted with your private key</h2>
			<progress id="decrypt_progress" value="0" max="5"></progress><br>
			<textarea id="decrypted" cols="125" rows="20" style="border: 1px solid green"></textarea>
			<form action="encrypt.php" method="post">
				<textarea id="public_key" name="public_key" readonly rows="0" cols="0" style="visibility: hidden; display: none;"><?php echo $pub_key; ?></textarea>
				<!--input type="hidden" id="public_key" name="public_key" value=""-->
				<input type="hidden" id="current_file" name="current_file" value="<?php echo $current_file; ?>">
				<input type="submit" value="< Previous" name="prev" id="prev" <?php echo $prev_file?"":"disabled"; ?>> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input type="submit" value="Next >" name="next" id="next" <?php echo $next_file?"":"disabled"; ?>>
			</form>
			<input type="hidden" id="genKey">
		<h2>3. The result reordered and human readable</h2>
			<iframe id="decrypted_blob" style="width: 60em; height: 1390px; border: 2px solid green;"></iframe>
		<script src="base64.js"></script>
		<script src="keydecrypt.js"></script>
		<?php
	}else{
		?>
		<p>Seems that you didn't sent your key? <a href="genkey_and_export.html">Try again</a></p>
		<?php
	}
	
?> 
</body>
</html>