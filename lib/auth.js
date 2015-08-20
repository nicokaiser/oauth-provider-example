'use strict';

var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var bcrypt = require('bcrypt');
var Tokens = require('./tokens');
var db = require('../db');

var tokenSecret = 'keyboard cat 3';
var accessTokens = new Tokens({type: 'access', secret: tokenSecret});

passport.use(new LocalStrategy(
    function (username, password, done) {
        db.users.findByUsername(username, function (err, user) {
            if (err) return done(err);
            if (!user) return done(null, false);
            bcrypt.compare(password, user.password, function (err1, res) {
                if (err) return done(err1);
                if (!res) return done(null, false);
                return done(null, user);
            });
        });
    }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    db.users.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use('basic', new BasicStrategy(
    function (clientId, clientSecret, done) {
        db.clients.findByClientId(clientId, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);
            if (client.clientSecret === clientSecret) return done(null, client);
            done(null, false);
        });
    }
));

passport.use('oauth2-client-password', new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        db.clients.findByClientId(clientId, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);
            if (client.clientSecret === clientSecret) return done(null, client);
            done(null, false);
        });
    }
));

passport.use('accessToken', new BearerStrategy(
    function (accessToken, done) {
        accessTokens.find(accessToken, function (err, token) {
            if (err) return done(err);
            done(null, {id: token.userId}, {scope: '*'});
        });
    }
));
