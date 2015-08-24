'use strict';

var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var morgan = require('morgan');
var passport = require('passport');
var session = require('express-session');
var oauth = require('./lib/oauth');


var app = express();

app.set('view engine', 'ejs');
//app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(session({name: 'oauth-provider.sid', secret: 'keyboard cat', resave: true, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());

require('./lib/auth');


// OpenID Connect 1.0 endpoints

app.get('/oauth2/auth', oauth.authorization);
app.post('/oauth2/auth', oauth.decision);
app.post('/oauth2/token', oauth.token);
app.get('/oauth2/userinfo', oauth.userinfo);
app.get('/.well-known/openid-configuration', oauth.discovery);


// Local login endpoints

app.get('/', function (req, res) {
    res.render('index', {user: req.user});
});

app.get('/login', function (req, res) {
    res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/'
}));

app.use('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});


// Protected resources

app.get('/restricted', passport.authenticate('accessToken', {session: false}), function (req, res) {
    res.send('Yay, you successfully accessed the restricted resource!');
});

app.get('/time', passport.authenticate('accessToken', {session: false}), function (req, res) {
    res.send(new Date());
});


// Error handler
/*
app.use(function (err, req, res, next) {
    res.render('error', {err: err});
});
*/

app.listen(3000);
