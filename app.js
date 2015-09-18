'use strict';

var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var morgan = require('morgan');
var passport = require('passport');
var session = require('express-session');
var FileStore = require('session-file-store')(session);
var cors = require('cors');


var provider = require('./lib/provider');


var app = express();

app.set('view engine', 'ejs');
app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(session({
    name: 'auth.sid',
    secret: 'ooDu8tiu2heiQu4eKesohK5xooTh0cu1',
    resave: true,
    saveUninitialized: true,
    store: new FileStore({
        path: './sessions',
        ttl: 1 * 24 * 3600,
        reapInterval: 1 * 60
    }),
    cookie: {
        maxAge: 1 * 24 * 3600 * 1000
    }
}));
app.use(passport.initialize());
app.use(passport.session());

require('./lib/auth');


// OpenID Connect 1.0 endpoints

app.use(provider({}));


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

app.options('/restricted', cors());
app.get('/restricted', cors(), passport.authenticate('accessToken', {session: false}), function (req, res) {
    res.send('Yay, you successfully accessed the restricted resource!');
});

app.options('/time', cors());
app.get('/time', cors(), passport.authenticate('accessToken', {session: false}), function (req, res) {
    res.send(new Date());
});


// Error handler

app.use(function (req, res) {
    var err = new Error('Not Found');
    err.status = err.statusCode = 404;
    res.status(404).render('error', {err: err});
});

app.use(function (err, req, res, next) {
    res.render('error', {err: err});
});


app.listen(3000);
