/* 
 * With help from the Web cryptography API samples 
 * Copyright (c) 2013 Nick Van den Bleeken
 * https://github.com/nvdbleek/web-crypto-samples
 */

/*******************************************************************************
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
 *******************************************************************************/
var metropolia = metropolia || {};
metropolia.keydecrypt = (function() {
	var keydecrypt = {
		version : "1.0"
	};
	
	//log to html
	var msg = document.getElementById('logMsg');
	//key pair
	var publicKey;
	var privateKey;
	//decrypt
	var resultArray;
	var blocCount;
	
	//utils
	str2ab = function (str) {
		var buf = new ArrayBuffer(str.length);
		var bufView = new Uint8Array(buf);
		for (var i=0, strLen=str.length; i<strLen; i++) {
			bufView[i] = str.charCodeAt(i);
		}
		return buf;
	}
	
	ab2str = function (buf) {
	  return String.fromCharCode.apply(null, new Uint8Array(buf));
	}
	
	//browser native or polycrypt fallback
	var webCrypto;
	var jwkAsObject = false; // Some implementations want the jwk as an object
	if (window.crypto && window.crypto.subtle) {
		console.log('Using standard Web Crytography API.');
		msg.innerHTML += 'Using standard Web Crytography API.<br>';
		webCrypto = window.crypto.subtle;
	} else if (window.msCrypto && window.msCrypto.subtle) {
		console.log('Using MS Web Crytography API.');
		msg.innerHTML += 'Using MS Web Crytography API.<br>';
		webCrypto = window.msCrypto.subtle;
	} else {
		console.log('No native Web Crytography API, falling back to polycrypt.');
		msg.innerHTML += 'No native Web Crytography API, falling back to polycrypt.<br>';
		webCrypto = window.polycrypt;
		jwkAsObject = true;
	}

	keydecrypt.generateKeyPair = function() {
		console.log("key gen?");
		msg.innerHTML += 'Go to key pair generation<br>';
		//generate public-private keys
		if(!(localStorage["fi.metropolia.key.public"] && localStorage["fi.metropolia.key.private"])){
			document.getElementById("time_warn").innerHTML = "Please wait. The key pair generation may take from 0.2 to more than 5 seconds.";
			var genOp = webCrypto.generateKey({
				name : "RSAES-PKCS1-v1_5",
				params: {
					modulusLength : 2048,
					publicExponent : new Uint8Array([ 0x01, 0x00, 0x01 ])
				}
			}, true, [ "encrypt", "decrypt" ]);
			genOp.onerror = function(e) {
				console.log('Error generating key pair');
				console.log(e);
				msg.innerHTML += 'Error generating key pair<br>';
				document.getElementById("time_warn").innerHTML = "";
			}
			genOp.oncomplete = function(e) {
				publicKey = e.target.result.publicKey;
				privateKey = e.target.result.privateKey;
				if(publicKey && privateKey){
					localStorage["fi.metropolia.key.public"] = JSON.stringify(publicKey);
					console.log(publicKey);
					//kids, never do that at home. the private key should be stored securely.
					localStorage["fi.metropolia.key.private"] = JSON.stringify(privateKey);
					msg.innerHTML += 'key generated: ';
					for(i = 0; i < 12; i++){
						msg.innerHTML += publicKey.key.substring(i*100, (i*100)+99) + '<br>';
					}
					msg.innerHTML += '<br>';
					//Export the public key
					var exportOp = webCrypto.exportKey("jwk", publicKey);
					exportOp.onerror = function(evt) {
						console.log('Error exporting public key');
						msg.innerHTML += 'Error exporting public key<br>';
						document.getElementById("time_warn").innerHTML = "";
					}
					exportOp.oncomplete = function(evt) {
						console.log('Exported public key');
						console.log(evt.target.result);
						msg.innerHTML += 'Exported public key<br>';
						//var n = evt.target.result.n.replace(/=/g, '').replace(/\-/g, '+').replace(/_/g, '/');
						var n = JSON.stringify(evt.target.result);
						console.log(n);
						localStorage["fi.metropolia.key.public.export"] = n;
						//localStorage["fi.metropolia.key.public.export"] = evt.target.result;
						document.getElementById('public_key').innerHTML = n;
						//document.getElementById('public_key').innerHTML = evt.target.result;
						document.getElementById('send_key').disabled = false;
						document.getElementById("time_warn").innerHTML = "";
					}
				}else{
					console.log('Error generating key pair?!?');
					console.log(e);
					msg.innerHTML += 'Error generating key pair<br>';
					document.getElementById("time_warn").innerHTML = "";
				}
			}
		}else{
			msg.innerHTML += 'key already exist<br>';
			document.getElementById('public_key').innerHTML = localStorage["fi.metropolia.key.public.export"];
			document.getElementById('send_key').disabled = false;
			document.getElementById("time_warn").innerHTML = "";
		}
	};

	keydecrypt.decrypt = function(data) {
		console.log('decrypt');
		console.log(data);
		if (privateKey == null) {
			console.log('not in cache, try from local storage');
			msg.innerHTML += '<br>Private key not in cache, try from local storage';
			privateKey = JSON.parse(localStorage["fi.metropolia.key.private"]);
		}
		if (privateKey == null) {
			console.log('this time we have a problem :D');
			msg.innerHTML += '<br>Private key lost :(';
			return;
		}
		
		//TODO fix polycrypt
		var alg;
		if (jwkAsObject) {
			alg = "RSAES-PKCS1-v1_5"
		}
		else {
			alg = { name : "RSAES-PKCS1-v1_5" };
		}
		var blocSize = 344;
		var i;
		var blocData = [];
		resultArray = [];
		blocCount = 0;
		document.getElementById("time_warn").innerHTML = "Please wait. The asynchronous decryption process has started, it will take few seconds.";
		document.getElementById("decrypt_progress").value = 0;
		for(i = 0; i < data.length/blocSize; i++){
			blocData.push(data.slice(i * blocSize, (i + 1) * blocSize));
		}
		console.log(blocData);
		var decryptOp = new Array(blocData.length);
		document.getElementById("decrypt_progress").max = blocData.length;
		//decrypt the data
		for(i = 0; i < blocData.length; i++){
			(function(closureI){
				decryptOp[closureI] = webCrypto.decrypt(alg, privateKey, new Uint8Array(Base64Binary.decodeArrayBuffer(blocData[closureI])));
				//console.log("ALIVE? " + closureI)
				
				decryptOp[closureI].onerror = function(evt) {
					console.log('Error decrypting data');
					msg.innerHTML += '<br>Error decrypting data :(';
					blocCount++;
					document.getElementById("decrypt_progress").value = blocCount;
					document.getElementById("decrypt_progress").innerHTML = '(' + blocCount + '/' + blocData.length + ')';
					if(blocCount === blocData.length)
						decryptedToBlob();
				}
		
				decryptOp[closureI].oncomplete = function(evt) {
					decryptedData = evt.target.result;
					blocCount++;
					document.getElementById("decrypt_progress").value = blocCount;
					document.getElementById("decrypt_progress").innerHTML = '(' + blocCount + '/' + blocData.length + ')';
		
					if (decryptedData) {
						//console.log('Decrypted data: ' + closureI);
						//msg.innerHTML += ' Decrypted data: ' + closureI + ' (' + blocCount + '/' + blocData.length + ')';
						resultArray[closureI] = ab2str(decryptedData);
						document.getElementById('decrypted').innerHTML += '\nDecrypted data: ' + closureI + ' (' + blocCount + '/' + blocData.length + ')\n' + resultArray[closureI];
					} else {
						console.log('Error decrypting data 2');
						msg.innerHTML += '<br>Error decrypting data :(';
					}
					if(blocCount === blocData.length)
						decryptedToBlob();
				};//decrypt
			})(i) //closure
		}
			
	};
	
	function decryptedToBlob(){
		console.log(resultArray);
		document.getElementById("time_warn").innerHTML = "";
		//hack to transform relative path to absolute hard-coded URL.
		var tmp = [];
		var j, hack;
		for(var i = 0; i < resultArray.length; i++){
			tmp = resultArray[i].split("=\"");
			if(tmp.length > 1){
				hack = "";
				for(j = 0; j < tmp.length - 1; j++){
					hack += tmp[j] + "=\"";
					if((tmp[j].endsWith("href") || tmp[j].endsWith("src")) && !tmp[j+1].startsWith("http://") && !tmp[j+1].startsWith("#"))
						hack += "http://users.metropolia.fi/~patricka/wcrypt-book/moby-dick/OPS/";
					console.log("tmp: " + tmp[j]);
				}
				hack += tmp[j];
				console.log("hack: " + hack);
				resultArray[i] = hack;
			}
		}
		//array to blob to be used as the iframe source.
		var blob = new Blob(resultArray, {type : 'application/xhtml+xml'});
		document.getElementById("decrypted_blob").src = URL.createObjectURL(blob);
	}


	// Hook up event listeners
	document.getElementById('genKey').onclick = function() {metropolia.keydecrypt.generateKeyPair()};
	document.getElementById('decrypt').onclick = function() {metropolia.keydecrypt.decrypt(document.getElementById('encrypted').innerHTML)};

	return keydecrypt;
})();