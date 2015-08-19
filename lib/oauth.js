'use strict';

var oauth2orize = require('oauth2orize');
var login = require('connect-ensure-login');
var passport = require('passport');
var bcrypt = require('bcrypt');
var jwt = require('jwt-simple');
var db = require('../db');

var tokenSecret = 'keyboard cat 3';

var server = oauth2orize.createServer();

server.serializeClient(function (client, done) {
    return done(null, client.clientId);
});

server.deserializeClient(function (clientId, done) {
    db.clients.findByClientId(clientId, function (err, client) {
        if (err) return done(err);
        return done(null, client);
    });
});

// grant: code
server.grant(oauth2orize.grant.code(function (client, redirectURI, user, ares, done) {
    var code = jwt.encode({
        sub: 'code',
        exp: now() + 3600,
        clientId: client.clientId,
        redirectURI: redirectURI,
        userId: user.id
    }, tokenSecret);
    done(null, code);
}));

// exchange: code => access_token + refresh_token
server.exchange(oauth2orize.exchange.code(function (client, code, redirectURI, done) {

    var authCode;
    try {
        authCode = jwt.decode(code, tokenSecret);
    } catch (err) {
        return done(err);
    }

    if (authCode.sub !== 'code') return done(null, false);
    if (client.clientId !== authCode.clientId) return done(null, false);
    if (redirectURI !== authCode.redirectURI) return done(null, false);

    var token = jwt.encode({
        sub: 'access',
        exp: now() + 3600,
        userId: authCode.userId,
        clientId: authCode.clientId
    }, tokenSecret);
    var refreshToken = jwt.encode({
        sub: 'refresh',
        userId:
        authCode.userId,
        clientId: authCode.clientId
    }, tokenSecret);

    done(null, token, refreshToken, {'expires_in': 3600});
    // FIXME: scope in token?
}));

// exchange: refresh_token => access_token
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    var token;
    try {
        token = jwt.decode(refreshToken, tokenSecret);
    } catch (err) {
        return done(err);
    }
    if (token.sub !== 'refresh') return done(null, false);
    if (client.clientId !== token.clientId) return done(null, false);
    var newAccessToken = jwt.encode({
        sub: 'access',
        exp: now() + 3600,
        userId: token.userId,
        clientId: token.clientId
    }, tokenSecret);
    var newRefreshToken = jwt.encode({
        sub: 'refresh',
        userId: token.userId,
        clientId: token.clientId
    }, tokenSecret);

    done(null, newAccessToken, newRefreshToken, {'expires_in': 3600});
    // FIXME: scope in token?
}));

// grant: access_token
server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
    var token = jwt.encode({
        sub: 'access',
        exp: now() + 3600,
        userId: user.id,
        clientId: client.clientId
    }, tokenSecret);

    return done(null, token, {'expires_in': 3600});
    // FIXME: scope in token?
}));

// exchange: clientId, clientSecret => access_token (Client Credentials)
server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {
    var token = jwt.encode({
        sub: 'access',
        exp: now() + 3600,
        clientId: client.clientId
    }, tokenSecret);

    return done(null, token, {'expires_in': 3600});
    // FIXME: scope in token?
}));

// exchange: username, password => access_token (Resource Owner Password)
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    db.users.findByUsername(username, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);
        bcrypt.compare(password, user.password, function (err1, res) {
            if (err1) return done(err1);
            if (!res) return done(null, false);

            var token = jwt.encode({
                sub: 'access',
                exp: now() + 3600,
                userId: user.id,
                clientId: client.clientId
            }, tokenSecret);
            var refreshToken = jwt.encode({
                sub: 'refresh',
                userId: user.id,
                clientId: client.clientId
            }, tokenSecret);

            return done(null, token, refreshToken, {'expires_in': 3600});
            // FIXME: scope in token?
        });
    });
}));

exports.authorization = [
    login.ensureLoggedIn(),
    server.authorization(function (clientID, redirectURI, done) {
        db.clients.findByClientId(clientID, function (err, client) {
            if (err) return done(err);
            // TODO: check redirectURI
            return done(null, client, redirectURI);
        });
    }), function (req, res) {
        res.render('dialog', {
            transactionID: req.oauth2.transactionID,
            user: req.user,
            client: req.oauth2.client
        });
    }
];

exports.decision = [
    login.ensureLoggedIn(),
    server.decision()
];

exports.token = [
    passport.authenticate(['clientBasic', 'clientPassword'], {session: false}),
    server.token(),
    server.errorHandler()
];

function now() {
    return Math.floor(Date.now() / 1000);
}
