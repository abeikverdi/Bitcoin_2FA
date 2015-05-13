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


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));

var crypto = require('crypto');

var BigInteger = require('bigi'); //npm install --save bigi@1.1.0
var ecurve = require('ecurve'); //npm install --save ecurve@1.0.0
var cs = require('coinstring'); //npm install --save coinstring@2.0.0

var privateKey = new Buffer("1df56359e825cabaca7aad5f95913f3d511385a865f520716c3dfd2028355abf", 'hex');

var ecparams = ecurve.getCurveByName('secp256k1');
var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(privateKey));
var x = curvePt.affineX.toBuffer(32);
var y = curvePt.affineY.toBuffer(32);
var publicKey = Buffer.concat([new Buffer([0x04]), x, y]);
var uPublickKey = "0421b5493cc52afe69ac36ba0fa8365457eeae86b44a8862deb7c38313e8cab44494f77d402905e826bf5f7fdb33ce71600e4d6440e45732ef041c0c579d6daa4c"
publicKey = curvePt.getEncoded(false); //false forces uncompressed public key
//console.log(publicKey.toString('hex'));

var sha = crypto.createHash('sha256').update(uPublickKey + '0:0:').digest();
x = crypto.createHash('sha256').update(sha).digest();
console.log("x: " + x.toString('hex'));

var XG = ecparams.G.multiply(BigInteger.fromBuffer(sha));
var curvePt2 = XG.add(curvePt);

var nextpublicKey = Buffer.concat([new Buffer([0x04]), x, y]);
var sha2 = crypto.createHash('sha256').update(nextpublicKey).digest()
var nextpublicKeyHash = crypto.createHash('rmd160').update(sha2).digest()
console.log(nextpublicKeyHash.toString('hex')); 
// => a1c2f92a9dacbd2991c3897724a93f338e44bdc1

// address of compressed public key
//console.log(cs.encode(pubkeyHash, 0x0))  //<-- 0x0 is f

//console.log(cs.encode(privateKey, 0x80)) //<--- 0x80 is for private addresses
// => 5Hx15HFGyep2CfPxsJKe2fXJsCVn5DEiyoeGGF6JZjGbTRnqfiD


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
