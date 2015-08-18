'use strict';

var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var session = require('express-session');
var oauth = require('./oauth');


var app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(session({name: 'oauth-provider.sid', secret: 'keyboard cat', resave: true, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());

require('./auth');


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

app.get('/authorization', oauth.authorization);

app.post('/authorization', oauth.decision);

app.post('/token', oauth.token);

app.get('/restricted', passport.authenticate('accessToken', {session: false}), function (req, res) {
    res.send('Yay, you successfully accessed the restricted resource!');
});

app.use(function (err, req, res, next) {
    res.render('error', {err: err});
});


app.listen(3000);
