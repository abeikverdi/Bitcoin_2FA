var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var routes = require('./routes/index');
var users = require('./routes/users');
var ecurve = require('ecurve');
var app = express();


/*********************
VIEW ENGINE SETUP
**********************/
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));


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
//var mPrivateKey = new Buffer("1df56359e825cabaca7aad5f95913f3d511385a865f520716c3dfd2028355abf", 'hex'); //Counterparty private key
var uCurvePt = ecurve.Point.decodeFrom(ecparams, uPublickKey);

//var uPublickKey = "0421b5493cc52afe69ac36ba0fa8365457eeae86b44a8862deb7c38313e8cab44494f77d402905e826bf5f7fdb33ce71600e4d6440e45732ef041c0c579d6daa4c";


publicKey = curvePt.getEncoded(false); //false forces uncompressed public key

//var cur = ecparams.Curve(x,y);
// var x1 = cur.affineX.toBuffer(32);
// var y1 = cur.affineY.toBuffer(32);
// console.log("x1: " + x1);

//Generating offset from user's public key
var sha = crypto.createHash('sha256').update(uPublickKey + '0:0:').digest();
var s = crypto.createHash('sha256').update(sha).digest(); //secret that should be sent to the user
console.log("s: " + s.toString('hex'));
var sG = ecparams.G.multiply(BigInteger.fromBuffer(s)); //Calculating the point from s*G which will be used to generate next public key
var x2 = sG.affineX.toBuffer(32);
var y2 = sG.affineY.toBuffer(32);
var publicKey2 = Buffer.concat([new Buffer([0x04]), x2, y2]);

//Generating next public key
var nxCurvePt = uCurvePt.add(sG); //Add user's public key with sG to generate new public key
var x1 = nxCurvePt.affineX.toBuffer(32);
var y1 = nxCurvePt.affineY.toBuffer(32);
var nxPublicKey = Buffer.concat([new Buffer([0x04]), x1, y1]);
//console.log(nxPublicKey.toString('hex'));
var sha2 = crypto.createHash('sha256').update(nxPublicKey).digest();
var nextpublicKeyHash = crypto.createHash('rmd160').update(sha2).digest();
//console.log(nextpublicKeyHash.toString('hex'));
console.log(cs.encode(nextpublicKeyHash, 0x0)) 


/*********************
WEB APP
**********************/
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

app.set('port', process.env.PORT || 3000);
var server = app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + server.address().port);
});

module.exports = app;
