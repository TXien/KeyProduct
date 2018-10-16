var bip39 = require("bip39")
var bip32 = require("bip32")
var bitcoin = require('bitcore-lib')
var HDKey = require('hdkey')
var bitcoinjs = require("bitcoinjs-lib")
var EthereumBip44 = require('ethereum-bip44');
var litecore = require('litecore');
var ethereum = require('ethereumjs-wallet')
const secp256k1 = require('secp256k1')
var sha256 = require("sha256")
var crypto = require('crypto');
		
		var mnemonic = bip39.generateMnemonic()
		var seed = bip39.mnemonicToSeedHex(mnemonic)
		var hdkey = HDKey.fromMasterSeed(new Buffer(seed, 'hex'))
		var HDkey = hdkey.privateExtendedKey
		var node = bip32.fromBase58(HDkey)
		var child = node.derivePath("m/44'/0'/0'/0/0")
		bitcoinKey = child.toWIF()


		var key = bitcoin.HDPrivateKey(HDkey);	
		var wallet = new EthereumBip44(key);
		//ethereum
		var ethereumKey = wallet.getPrivateKey(0).toString('hex')
		var ethereumAddress = wallet.getAddress(0)
		var keyPair = bitcoinjs.ECPair.fromWIF(bitcoinKey)
		var bitcoinAddress = keyPair.getAddress()

		//litecoin
		//var litecore = require('litecore');
		var privateKey = new litecore.PrivateKey(ethereumKey);
		var litecoinKey = privateKey.toWIF()
		var litecoinAddress = privateKey.toAddress().toString();

                var bitcoinprivateKey = new bitcoin.PrivateKey(ethereumKey);
                var btcAddress = bitcoinprivateKey.toAddress().toString();
                var btcKey = bitcoinprivateKey.toWIF()
                var cic = ethereum.fromPrivateKey(Buffer.from(ethereumKey,"hex"))
                var cicpub = cic.getPublicKey().toString("hex");

		var re = secp256k1.publicKeyCreate(Buffer.from(ethereumKey,"hex"), false).slice(1)
		var cicAddress = /*"cx"+*/sha256(re.toString("hex")).substr(24,64)
		
		var re = {
			"version":"0.01","mnemonic":mnemonic,"HDkey":HDkey,
				"litecoin":
				{"privateKey":litecoinKey,"address":litecoinAddress},
				"bitcoin":
				{"privateKey":btcKey,"address":btcAddress},
				"ethereum":
				{"privateKey":ethereumKey,"address":ethereumAddress},
				"cicandguc":
				{"privateKey":ethereumKey,"address":cicAddress}
				}
		console.log(re)
        
