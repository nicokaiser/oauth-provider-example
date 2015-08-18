'use strict';

var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var crypto = require('crypto');
var bcrypt = require('bcrypt');
var db = require('./db');

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

passport.use('clientBasic', new BasicStrategy(
    function (clientId, clientSecret, done) {
        db.clients.findByClientId(clientId, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);

            if (client.clientSecret === clientSecret) return done(null, client);
            else return done(null, false);
        });
    }
));

passport.use('clientPassword', new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        db.clients.findByClientId(clientId, function (err, client) {
            if (err) return done(err);
            if (!client) return done(null, false);

            if (client.clientSecret === clientSecret) return done(null, client);
            else return done(null, false);
        });
    }
));

passport.use('accessToken', new BearerStrategy(
    function (accessToken, done) {
        var accessTokenHash = crypto.createHash('sha1').update(accessToken).digest('hex');
        db.accessTokens.findByToken(accessTokenHash, function (err, token) {
            if (err) return done(err);
            if (!token) return done(null, false);
            if (new Date() > token.expirationDate) {
                db.accessTokens.removeByToken(accessTokenHash, done);
            } else {
                db.users.findById(token.userId, function (err1, user) {
                    if (err1) return done(err1);
                    if (!user) return done(null, false);
                    // no use of scopes for now
                    var info = {scope: '*'};
                    done(null, user, info);
                });
                // FIXME: when using Client Credentials, there is no user.
                /*
                db.clients.findById(token.clientId, function (err1, client) {
                    if (err1) return done(err1);
                    if (!client) return done(null, false);
                    done(null, client, { scope: '*' });
                });
                */
            }
        });
    }
));
