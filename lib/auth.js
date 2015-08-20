'use strict';

var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var db = require('../db');

passport.use(new LocalStrategy(
    function (username, password, done) {
        db.users.checkCredentials(username, password, function (err, res) {
            if (err) return done(err);
            if (!res) return done(null, false);
            return db.users.findByUsername(username, done);
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
        db.accessTokens.get(accessToken, function (err, token) {
            if (err) return done(err);
            done(null, {id: token.userId}, {scope: token.scope || '*'});
        });
    }
));
