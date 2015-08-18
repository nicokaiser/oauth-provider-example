'use strict';

var oauth2orize = require('oauth2orize');
var crypto = require('crypto');
var login = require('connect-ensure-login');
var passport = require('passport');
var bcrypt = require('bcrypt');
var db = require('./db');

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
    var code = uid(16);

    db.authorizationCodes.save({
        code: code,
        clientId: client.clientId,
        redirectURI: redirectURI,
        userId: user.id
    }, function(err) {
        if (err) return done(err);
        done(null, code);
    });
}));

// exchange: code => access_token + refresh_token
server.exchange(oauth2orize.exchange.code(function (client, code, redirectURI, done) {
    db.authorizationCodes.findByCode(code, function (err, authCode) {
        if (err) return done(err);
        if (!authCode) return done(null, false);
        if (client.clientId !== authCode.clientId) return done(null, false);
        if (redirectURI !== authCode.redirectURI) return done(null, false);

        db.authorizationCodes.removeByCode(code, function (err1) {
            if (err1) return done(err1);
            var token = uid(256);
            var refreshToken = uid(256);
            var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
            var refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex');

            var expirationDate = new Date(new Date().getTime() + (3600 * 1000));

            db.accessTokens.save({
                token: tokenHash,
                expirationDate: expirationDate,
                userId: authCode.userId,
                clientId: authCode.clientId
            }, function (err2) {
                if (err2) return done(err2);
                db.refreshTokens.save({
                    refreshToken: refreshTokenHash,
                    clientId: authCode.clientId,
                    userId: authCode.userId
                }, function (err3) {
                        if (err3) return done(err3);
                        done(null, token, refreshToken, {'expires_in': expirationDate});
                    }
                );
            });
        });
    });
}));

// exchange: refresh_token => access_token
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    var refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex');

    db.refreshTokens.findByRefreshToken(refreshTokenHash, function (err, token) {
        if (err) return done(err);
        if (!token) return done(null, false);
        if (client.clientId !== token.clientId) return done(null, false);

        var newAccessToken = uid(256);
        var accessTokenHash = crypto.createHash('sha1').update(newAccessToken).digest('hex');

        var expirationDate = new Date(new Date().getTime() + (3600 * 1000));

        db.accessTokens.updateByUserId(token.userId, {
            token: accessTokenHash,
            scope: scope,
            expirationDate: expirationDate
        }, function (err1) {
                if (err) return done(err1);
                done(null, newAccessToken, refreshToken, {'expires_in': expirationDate});
            }
        );
    });
}));

// grant: access_token
server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
    var token = uid(256);
    var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
    var expirationDate = new Date(new Date().getTime() + (3600 * 1000));

    db.accessTokens.save({
        token: tokenHash,
        expirationDate: expirationDate,
        userId: user.id,
        clientId: client.clienId
    }, function(err) {
            if (err) return done(err);
            return done(null, token, {'expires_in': expirationDate.toISOString()});
        }
    );
}));

// exchange: clientId, clientSecret => access_token (Client Credentials)
server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {
    var token = uid(256);
    var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
    var expiresIn = 1800;
    var expirationDate = new Date(new Date().getTime() + (expiresIn * 1000));

    db.accessTokens.save({
        token: tokenHash,
        expirationDate: expirationDate,
        clientId: client.clientId,
        scope: scope
    }, function(err) {
        if (err) return done(err);
        return done(null, token, {'expires_in': expiresIn});
    });
}));

// exchange: username, password => access_token (Resource Owner Password)
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    db.users.findByUsername(username, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);
        bcrypt.compare(password, user.password, function (err1, res) {
            if (err1) return done(err1);
            if (!res) return done(null, false);

            var token = uid(256);
            var refreshToken = uid(256);
            var tokenHash = crypto.createHash('sha1').update(token).digest('hex');
            var refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex');

            var expirationDate = new Date(new Date().getTime() + (3600 * 1000));

            db.accessTokens.save({
                token: tokenHash,
                expirationDate: expirationDate,
                clientId: client.clientId,
                userId: user.id,
                scope: scope
            }, function (err2) {
                if (err2) return done(err2);
                db.refreshTokens.save({
                    refreshToken: refreshTokenHash,
                    clientId: client.clientId,
                    userId: user.id
                }, function (err3) {
                    if (err3) return done(err3);
                    done(null, token, refreshToken, {'expires_in': expirationDate});
                });
            });
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

function uid(len) {
    var buf = [];
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charlen = chars.length;

    for (var i = 0; i < len; ++i) {
        buf.push(chars[getRandomInt(0, charlen - 1)]);
    }

    return buf.join('');
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
