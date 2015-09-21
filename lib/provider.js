'use strict';

var express = require('express');
var oauth2orize = require('oauth2orize');
var oauth2orizeOpenid = require('oauth2orize-openid');
var jwt = require('jsonwebtoken');
var merge = require('utils-merge');
var debug = require('debug')('oauth-provider');

var db = require('../db');
var defaultConfig = require('./default-config');


var router = express.Router();
var server = oauth2orize.createServer();
var config = {};


// Client serialization

server.serializeClient(function (client, done) {
    return done(null, client.clientId);
});

server.deserializeClient(function (clientId, done) {
    db.clients.findByClientId(clientId, function (err, client) {
        if (err) return done(err);
        return done(null, client);
    });
});


// OAuth 2.0 grant types

// 'code' grant type (Authorization Code Flow)
server.grant(oauth2orize.grant.code(issueCode));

// 'token' grant type (Implicit Flow)
server.grant(oauth2orize.grant.token(issueToken));


// OpenID Connect 1.0 grant types

// OpenID Connect extensions
server.grant(oauth2orizeOpenid.extensions());

// 'id_token' grant type (Implicit Flow)
server.grant(oauth2orizeOpenid.grant.idToken(issueIDToken));

// 'id_token token' grant type (Implicit Flow)
server.grant(oauth2orizeOpenid.grant.idTokenToken(issueToken, issueIDToken));

// 'code id_token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeIdToken(issueCode, issueIDToken));

// 'code token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeToken(issueToken, issueCode));

// 'code id_token token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeIdTokenToken(issueToken, issueCode, issueIDToken));


function issueToken(client, user, ares, done) {
    debug('Issuing Access Token');

    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        scope: ares.scope
    }, function (err, accessToken) {
        if (err) return done(err);

        // TODO: check ares.scope for "offline_access"

        db.refreshTokens.create({
            clientId: client.clientId,
            userId: user.id,
            scope: ares.scope
        }, function (err2, refreshToken) {
            if (err2) return done(err2);
            return done(null, accessToken, {
                'refresh_token': refreshToken,
                'expires_in': config.accessTokenTTL
            });
        });
    });
}

function issueCode(client, redirectURI, user, ares, done) {
    debug('Issuing Authorization Code');

    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        redirectURI: redirectURI,
        scope: ares.scope
    }, done);
}

function issueIDToken(client, user, scope, req, done) {
    debug('Issuing ID Token');

    done(null, jwt.sign({
        iss: config.baseUrl,
        sub: user.id,
        aud: client.clientId,
        nonce: req.nonce
    }, config.idTokenSecret, {
        algorithm: config.idTokenAlgorithm,
        expiresInSeconds: config.idTokenTTL
    }));
}


// OAuth 2.0 exchanges

// code => access_token + refresh_token (Authorization Code Flow)
server.exchange(oauth2orize.exchange.authorizationCode(function (client, code, redirectURI, done) {
    debug('OAuth: exchange code => access_token + refresh_token');

    db.authCodes.get(code, function (err, data) {
        if (err) return done(err);
        if (data.clientId !== client.clientId) return done(null, false);
        if (data.redirectURI !== redirectURI) {
            return done(new oauth2orize.AuthorizationError(
                'The redirect_uri MUST match the registered callback URL for this application.',
                'redirect_uri_mismatch'
            ));
        }

        db.authCodes.remove(code, function () {});

        db.accessTokens.create({
            clientId: data.clientId,
            userId: data.userId,
            scope: data.scope
        }, function (err1, accessToken) {
            if (err1) return done(err1);

            db.refreshTokens.create({
                clientId: data.clientId,
                userId: data.userId,
                scope: data.scope
            }, function (err2, refreshToken) {
                if (err2) return done(err2);
                return done(null, accessToken, refreshToken, {'expires_in': config.accessTokenTTL});
            });
        });
    });
}));

// refresh_token => access_token (Authorization Code Flow)
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    debug('OAuth: exchange refresh_token => access_token');

    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.refreshTokens.get(refreshToken, function (err, token) {
        if (err) return done(err);
        if (token.clientId !== client.clientId) return done(null, false);
        if (token.scope !== scope) return done(null, false);

        db.refreshTokens.remove(refreshToken, function () {});

        db.accessTokens.create({
            clientId: token.clientId,
            userId: token.userId,
            scope: scope
        }, function (err1, newAccessToken) {
            if (err1) return done(err1);

            db.refreshTokens.create({
                clientId: token.clientId,
                userId: token.userId,
                scope: scope
            }, function (err2, newRefreshToken) {
                if (err2) return done(err2);
                done(null, newAccessToken, newRefreshToken, {'expires_in': config.accessTokenTTL});
            });
        });
    });
}));

// clientId, clientSecret => access_token (Client Credentials Flow)
server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {
    debug('OAuth: exchange clientId, clientSecret => access_token');

    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.accessTokens.create({
        clientId: client.clientId,
        scope: scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': config.accessTokenTTL});
    });
}));

// username, password => access_token (Resource Owner Password Flow)
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    debug('OAuth: exchange username, password => access_token');

    if (!client.trusted) return done(null, false); // only allowed for trusted clients

    db.users.checkCredentials(username, password, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);

        db.accessTokens.create({
            clientId: client.clientId,
            userId: user.id,
            scope: scope
        }, function (err2, accessToken) {
            if (err2) return done(err2);

            db.refreshTokens.create({
                clientId: client.clientId,
                userId: user.id,
                scope: scope
            }, function (err3, refreshToken) {
                if (err3) return done(err3);
                return done(null, accessToken, refreshToken, {'expires_in': config.accessTokenTTL});
            });
        });
    });
}));


module.exports = function (opts) {
    opts = opts || {};
    config = merge(defaultConfig, opts);

    db.accessTokens.ttl = config.accessTokenTTL;
    db.accessTokens.secret = config.accessTokenSecret;
    db.accessTokens.algorithm = config.accessTokenAlgorithm;

    db.refreshTokens.ttl = config.refreshTokenTTL;
    db.authCodes.ttl = config.authCodeTTL;

    router.use(require('./routes/authorization')(config, server));
    router.use(require('./routes/token')(config, server));
    router.use(require('./routes/userinfo')(config));
    router.use(require('./routes/tokeninfo')(config));
    router.use(require('./routes/discovery')(config));
    router.use(require('./routes/jwks')(config));

    return router;
};
