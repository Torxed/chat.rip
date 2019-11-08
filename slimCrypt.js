/**
 * This library is ment to ease and separate the cryptographical
 * functions of the Pytrix framework. Everything in here should be strictly
 * concerning cryptographical functions.
*/

// a CRC32 function, borrowed from: https://stackoverflow.com/a/50579690/929999 (Do go there and up-vote it)
var crc32=function(r){for(var a,o=[],c=0;c<256;c++){a=c;for(var f=0;f<8;f++)a=1&a?3988292384^a>>>1:a>>>1;o[c]=a}for(var n=-1,t=0;t<r.length;t++)n=n>>>8^o[255&(n^r.charCodeAt(t))];return(-1^n)>>>0};

// TODO: Replace print() with console.log() (It was a convenience thing)

let key_format = 'AES-CBC';
let key_size = 256;

function load_public_key(key, func) {
	let options = {   //these are the algorithm options
		name: "RSA-OAEP",
		hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
	};
	window.crypto.subtle.importKey("jwk", key, options, true, ["wrapKey"]).then(function(key_data){
		func(key_data);
	}).catch(function(err){
		console.error(err);
	});
}

function load_key(id, func) {
	let key_data = JSON.parse(localStorage.getItem("key_storage"))[id];

	if(key_data && typeof key_data !== "undefined" && sizeOf(key_data.key)) {
		key_data.iv = new Uint8Array(JSON.parse("["+atob(key_data.iv)+"]"));
		let options = {
			name: key_format,
			iv: key_data.iv
		};
		window.crypto.subtle.importKey("jwk", key_data.key, options, true, ["encrypt", "decrypt"]).then(function(key){
			func(key, key_data.iv);
		})
		.catch(function(err){
			console.error(err);
		});
	}
}

function store_key(id, key) {
	window.crypto.subtle.exportKey("jwk", key).then(function(key_data){
		if(localStorage.getItem("lock")) {
			return null;
		}
		localStorage.setItem("lock", true);
		let key_storage = localStorage.getItem("key_storage");
		if(typeof key_storage === "undefined" || key_storage === null)
			key_storage = {};
		else
			key_storage = JSON.parse(key_storage);

		let iv = btoa(window.crypto.getRandomValues(new Uint8Array(16)));
		key_storage[id] = {"key": key_data, "iv": iv};
		localStorage.setItem("key_storage", JSON.stringify(key_storage));
		localStorage.removeItem("lock");
	})
	.catch(function(err){
		console.error("Couldn't store key in localStorage:");
		console.error(err);
	});
}

function generate_key(id) {
	window.crypto.subtle.generateKey({
		name: key_format,
		length: key_size
	}, true, ["encrypt", "decrypt"]).then(function(key) { // false = Extractable key (via .exportKey()) ?
		store_key(id, key);
	});
}

function generate_identity(callback) {
	console.log('moo');
	/** 
	 * Stores a identity in localStorage['identity']
	 * SHA-256 / RSA-OAEP
	*/
	let options = {
		name: "RSA-OAEP",
		modulusLength: 2048, //can be 1024, 2048, or 4096
		publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
		hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
	};

	// ["encrypt", "decrypt"]
	window.crypto.subtle.generateKey(options, true, ["wrapKey", "unwrapKey"]).then(function(key){
		// Iterate over both:
		// * privateKey
		// * publicKey
		// And store those, each with individual timers (respecting each others lock)
		for(let key_obj in {'publicKey':true, 'privateKey':true}) {
			window.crypto.subtle.exportKey("jwk", key[key_obj]).then(function(key_data) {
				callback(key_obj, key_data);
				/*
				setTimer(key_obj+"IdentityExport", function() {
					if(!localStorage.getItem("lock")) {
						localStorage.setItem("lock", true);

						let identity = localStorage.getItem("identity");
						if(!identity || typeof identity === "undefined")
							identity = {};
						else
							identity = JSON.parse(identity);

						identity[key_obj] = key_data;
						localStorage.setItem("identity", JSON.stringify(identity));

						localStorage.removeItem("lock");
						clearTimer(key_obj+"IdentityExport");
					} else {
						print(key_obj+"IdentityExport waiting for lock");
					}
				}, 500)
				*/
			}).catch(function(err){
				console.error("Error in exporting key to identity:");
				console.error(err);
			});
			
		}
	}).catch(function(err){
		console.error("Error in generating identity key-pair:");
		console.error(err);
	});
}

function encrypt(data, key_data, iv, func=null) {
	let encoder = new TextEncoder("utf-8");
	let bytes = encoder.encode(data);

	let options = {
		name: key_format,
		iv: iv
	};

	window.crypto.subtle.encrypt(options, key_data, bytes).then(function(encrypted){
		let b64_msg = btoa(new Uint8Array(encrypted));

		if (func)
			func(b64_msg);
	});
}

function decrypt(data, key, iv, func=null) {
	let array = JSON.parse("["+atob(data)+"]");
	let bytes = new Uint8Array(array);

	let options = {
		name: key_format,
		iv: iv
	};

	window.crypto.subtle.decrypt(options, key, bytes).then(function(decrypted_message) {
		if (func)
			func(decrypted_message);
		else
			print("Decrypted message: " + decrypted_message);
	}).catch(function(err) {
		print("Could not decrypt message.");
		print(err);
	});
}

function load_private_key(private_key, func=null) {
	window.crypto.subtle.importKey("jwk", private_key, {name: "RSA-OAEP", hash: {name: "SHA-256"}}, false, ["unwrapKey"]).then(function(privateKey){
		func(privateKey);
	}).catch(function(err){
		console.error(err);
	});
}

function extract_AES_key(key_data, private_key, func=null) {
	let options = {
		name: "RSA-OAEP",
		hash: {name: "SHA-256"},
	}

	// AES-GCM is better, change on AES generation!!! TODO/FIXME
	window.crypto.subtle.unwrapKey("raw", key_data, private_key, options, {name: "AES-CBC", length: 256}, true, ["encrypt", "decrypt"]).then(function(AES_key){
		func(AES_key);
	}).catch(function(err){
		console.error(err);
	});
}

function wrap_AES_key(key, public_key, func=null) {
	let options = {   //these are the wrapping key's algorithm options
		name: "RSA-OAEP",
		hash: {name: "SHA-256"},
	};
	window.crypto.subtle.wrapKey("raw", key, public_key, options).then(function(wrapped){
		if (func)
			func(wrapped);
	}).catch(function(err){
		console.error(err);
	});
}
