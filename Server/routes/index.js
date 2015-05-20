var express = require('express');
var router = express.Router();
global.localStorage = require('localStorage')
var store = require('store')



/*********************
BITCOIN QRCODE
**********************/



/* GET home page. */
router.get('/:id', function(req, res, next) {
	var i = req.params.id

/*********************
BITCOIN CRYPTO
**********************/
var crypto = require('crypto');
var BigInteger = require('bigi');
var ecurve = require('ecurve'); 
var cs = require('coinstring'); 

//Setting up secp256k1 EC
var ecparams = ecurve.getCurveByName('secp256k1');

//Counterparty keys
var privateKey = new Buffer("2df56359e825cabaca7aad5f95913f3d511385a865f520716c3dfd2028355abf", 'hex'); //Counterparty private key
var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(privateKey));
var x = curvePt.affineX.toBuffer(32);
var y = curvePt.affineY.toBuffer(32);
var publicKey = Buffer.concat([new Buffer([0x04]), x, y]);

//User public key
var uPublickKey = new Buffer('0421b5493cc52afe69ac36ba0fa8365457eeae86b44a8862deb7c38313e8cab44494f77d402905e826bf5f7fdb33ce71600e4d6440e45732ef041c0c579d6daa4c', 'hex')
var uCurvePt = ecurve.Point.decodeFrom(ecparams, uPublickKey);
publicKey = curvePt.getEncoded(false); //false forces uncompressed public key

//Generating offset from user's public key
console.log("i " + i);
var sha = crypto.createHash('sha256').update(uPublickKey + i).digest();
var s = crypto.createHash('sha256').update(sha).digest(); //secret that should be sent to the user
console.log("s: " + s.toString('hex'));
var sG = ecparams.G.multiply(BigInteger.fromBuffer(s)); //Calculating the point from s*G which will be used to generate the public key
var x2 = sG.affineX.toBuffer(32);
var y2 = sG.affineY.toBuffer(32);
var publicKey2 = Buffer.concat([new Buffer([0x04]), x2, y2]);

//Generating new public key
var nwCurvePt = uCurvePt.add(sG); //Add user's public key with sG to generate new public key
var x1 = nwCurvePt.affineX.toBuffer(32);
var y1 = nwCurvePt.affineY.toBuffer(32);
var nwPublicKey = Buffer.concat([new Buffer([0x04]), x1, y1]);
var sha2 = crypto.createHash('sha256').update(nwPublicKey).digest();
var newpublicKeyHash = crypto.createHash('rmd160').update(sha2).digest();
console.log(cs.encode(newpublicKeyHash, 0x0)) 

var j = parseInt(i)+1;
	console.log("i+1 " + j);
var sha4 = crypto.createHash('sha256').update(uPublickKey + j).digest();
var s2 = crypto.createHash('sha256').update(sha4).digest(); //secret that should be sent to the user
var sG2 = ecparams.G.multiply(BigInteger.fromBuffer(s2)); //Calculating the point from s2*G which will be used to generate next public key

//Generating next public key
var nxCurvePt = uCurvePt.add(sG2); //Add user's public key with sG2 to generate new public key
var x1 = nxCurvePt.affineX.toBuffer(32);
var y1 = nxCurvePt.affineY.toBuffer(32);
var nxPublicKey = Buffer.concat([new Buffer([0x04]), x1, y1]);
var sha3 = crypto.createHash('sha256').update(nxPublicKey).digest();
var nextpublicKeyHash = crypto.createHash('rmd160').update(sha3).digest();
console.log(cs.encode(nextpublicKeyHash, 0x0))




  res.render('index', { 
  	title: 'Two-Factor Authentication',
  	secret: s.toString('hex'),
  	address: cs.encode(nextpublicKeyHash, 0x0),
   });
});

module.exports = router;
