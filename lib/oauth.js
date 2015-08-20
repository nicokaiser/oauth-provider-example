'use strict';

var oauth2orize = require('oauth2orize');
var ensureLogin = require('connect-ensure-login');
var passport = require('passport');
var bcrypt = require('bcrypt');
var db = require('../db');

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
    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + 600,
        redirectURI: redirectURI,
        scope: ares.scope
    }, function (err, code) {
        if (err) return done(err);
        done(null, code);
    });
}));

// exchange: code => access_token + refresh_token
server.exchange(oauth2orize.exchange.code(function (client, code, redirectURI, done) {
    db.authCodes.get(code, function (err, data) {
        if (err) return done(err);
        if (data.clientId !== client.clientId) return done(null, false);
        if (data.redirectURI !== redirectURI) {
            return done(new oauth2orize.AuthorizationError(
                'The redirect_uri MUST match the registered callback URL for this application.',
                'redirect_uri_mismatch'
            ));
        }

        db.accessTokens.create({
            clientId: data.clientId,
            userId: data.userId,
            expires: now() + 3600,
            scope: data.scope
        }, function (err1, accessToken) {
            if (err1) return done(err1);

            db.refreshTokens.create({
                clientId: data.clientId,
                userId: data.userId,
                scope: data.scope
            }, function (err2, refreshToken) {
                if (err2) return done(err2);
                return done(null, accessToken, refreshToken, {'expires_in': 3600});
            });
        });
    });
}));

// exchange: refresh_token => access_token
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.refreshTokens.get(refreshToken, function (err, token) {
        if (err) return done(err);
        if (token.clientId !== client.clientId) return done(null, false);
        if (token.scope !== scope) return done(null, false);

        db.accessTokens.create({
            clientId: token.clientId,
            userId: token.userId,
            expires: now() + 3600,
            scope: scope
        }, function (err1, newAccessToken) {
            if (err1) return done(err1);

            db.refreshTokens.create({
                clientId: token.clientId,
                userId: token.userId,
                expires: now() + 3600,
                scope: scope
            }, function (err2, newRefreshToken) {
                if (err2) return done(err2);
                done(null, newAccessToken, newRefreshToken, {'expires_in': 3600});
            });
        });
    });
}));

// grant: access_token
server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + 3600,
        scope: ares.scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': 3600});
    });
}));

// exchange: clientId, clientSecret => access_token (Client Credentials)
server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {
    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.accessTokens.create({
        clientId: client.clientId,
        expires: now() + 3600,
        scope: scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': 3600});
    });
}));

// exchange: username, password => access_token (Resource Owner Password)
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.users.findByUsername(username, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);

        bcrypt.compare(password, user.password, function (err1, res) {
            if (err1) return done(err1);
            if (!res) return done(null, false);

            db.accessTokens.create({
                clientId: client.clientId,
                userId: user.id,
                expires: now() + 3600,
                scope: scope
            }, function (err2, accessToken) {
                if (err2) return done(err2);

                db.refreshTokens.create({
                    clientId: client.clientId,
                    userId: user.id,
                    expires: now() + 3600,
                    scope: scope
                }, function (err3, refreshToken) {
                    if (err3) return done(err3);
                    return done(null, accessToken, refreshToken, {'expires_in': 3600});
                });
            });
        });
    });
}));

exports.authorization = [
    ensureLogin.ensureLoggedIn(),
    server.authorization(function (clientId, redirectURI, scope, done) {
        db.clients.findByClientId(clientId, function (err, client) {
            if (err) return done(err);
            if (client && client.redirectURI && (client.redirectURI !== redirectURI)) {
                return done(new oauth2orize.AuthorizationError(
                    'The redirect_uri MUST match the registered callback URL for this application.',
                    'redirect_uri_mismatch'
                ));
            }
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
    ensureLogin.ensureLoggedIn(),
    server.decision()
];

exports.token = [
    passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
    server.token(),
    server.errorHandler()
];

function now() {
    return Math.floor(Date.now() / 1000);
}
