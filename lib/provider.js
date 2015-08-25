'use strict';

var express = require('express');
var oauth2orize = require('oauth2orize');
var oauth2orizeOpenid = require('oauth2orize-openid');
var ensureLogin = require('connect-ensure-login');
var jwt = require('jwt-simple');
var passport = require('passport');
var merge = require('utils-merge');
var fs = require('fs');
var path = require('path');
var rsaPemToJwk = require('rsa-pem-to-jwk');
var debug = require('debug')('oauth-provider');
var cors = require('cors');

var db = require('../db');


// Default configuration

var defaultConfig = {
    baseUrl: 'http://localhost:3000',

    // Endpoints
    authorizationEndpoint: '/oauth2/auth',
    tokenEndpoint: '/oauth2/token',
    userInfoEndpoint: '/oauth2/userinfo',
    jwksUri: '/oauth2/certs',

    // Token settings
    idTokenTTL: 3600,
    idTokenAlg: 'RS256',
    accessTokenTTL: 3600,
    authCodeTTL: 600,

    key: fs.readFileSync(path.resolve(__dirname, '../key.pem'))
};


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


// OpenID Connect 1.0 grant types

// 'id_token' grant type (Implicit Flow)
server.grant(oauth2orizeOpenid.grant.idToken(function (client, user, done) {
    debug('OpenID Connect: "id_token" grant');
    createIdToken(client, user, done);
}));

// 'id_token token' grant type (Implicit Flow)
server.grant(oauth2orizeOpenid.grant.idTokenToken(function (client, user, ares, done) {
    debug('OpenID Connect: "id_token token" grant (token)');
    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.accessTokenTTL,
        scope: ares.scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': config.accessTokenTTL});
    });
}, function (client, user, done) {
    debug('OpenID Connect: "id_token token" grant (id_token)');
    createIdToken(client, user, done);
}));

// 'code id_token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeIdToken(function (client, redirectURI, ares, user, done) {
    debug('OpenID Connect: "code id_token" grant (code)');
    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.authCodeTTL,
        redirectURI: redirectURI,
        scope: ares.scope
    }, done);
}, function (client, user, done) {
    debug('OpenID Connect: "code id_token" grant (id_token)');
    createIdToken(client, user, done);
}));

// 'code token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeToken(function (client, user, ares, done) {
    debug('OpenID Connect: "code token" grant (token)');
    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.accessTokenTTL,
        scope: ares.scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': config.accessTokenTTL});
    });
}, function (client, redirectURI, user, ares, done) {
    debug('OpenID Connect: "code token" grant (code)');
    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.authCodeTTL,
        redirectURI: redirectURI,
        scope: ares.scope
    }, done);
}));

// 'code id_token token' grant type (Hybrid Flow)
server.grant(oauth2orizeOpenid.grant.codeIdTokenToken(function (client, user, ares, done) {
    debug('OpenID Connect: "code id_token token" grant (token)');
    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.accessTokenTTL,
        scope: ares.scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': config.accessTokenTTL});
    });
}, function (client, redirectURI, user, ares, done) {
    debug('OpenID Connect: "code id_token token" grant (code)');
    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.authCodeTTL,
        redirectURI: redirectURI,
        scope: ares.scope
    }, done);
}, function (client, user, done) {
    debug('OpenID Connect: "code id_token token" grant (id_token)');
    createIdToken(client, user, done);
}));


// OAuth 2.0 grant types

// 'code' grant type (Authorization Code Flow)
server.grant(oauth2orize.grant.code(function (client, redirectURI, user, ares, done) {
    debug('OAuth: "code" grant');
    db.authCodes.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.authCodeTTL,
        redirectURI: redirectURI,
        scope: ares.scope
    }, done);
}));

// 'token' grant type (Implicit Flow)
server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
    debug('OAuth: "token" grant');
    db.accessTokens.create({
        clientId: client.clientId,
        userId: user.id,
        expires: now() + config.accessTokenTTL,
        scope: ares.scope
    }, function (err, token) {
        if (err) return done(err);
        done(null, token, {'expires_in': config.accessTokenTTL});
    });
}));


// OAuth 2.0 exchanges

// code => access_token + refresh_token (Authorization Code Flow)
server.exchange(oauth2orize.exchange.code(function (client, code, redirectURI, done) {
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

        db.accessTokens.create({
            clientId: data.clientId,
            userId: data.userId,
            expires: now() + config.accessTokenTTL,
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

        db.accessTokens.create({
            clientId: token.clientId,
            userId: token.userId,
            expires: now() + config.accessTokenTTL,
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
        expires: now() + config.accessTokenTTL,
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

    db.users.checkCredentials(username, password, function (err, res) {
        if (err) return done(err);
        if (!res) return done(null, false);

        db.users.findByUsername(username, function (err1, user) {
            if (err) return done(err);
            if (!user) return done(null, false);

            db.accessTokens.create({
                clientId: client.clientId,
                userId: user.id,
                expires: now() + config.accessTokenTTL,
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
    });
}));


function createIdToken(client, user, done) {
    done(null, jwt.encode({
        'iss': config.baseUrl,
        'sub': user.id,
        'aud': client.clientId,
        'exp': now() + config.idTokenTTL,
        'iat': now(),
        'auth_time': now()
    }, config.key, config.idTokenAlg));
}

function now() {
    return Math.floor(Date.now() / 1000);
}


module.exports = function (opts) {
    opts = opts || {};
    config = merge(defaultConfig, opts);

    // Authorization Endpoint (GET)
    router.get(config.authorizationEndpoint,
        function (req, res, next) {
            var body = req.body || {};
            req._prompt = req.query.prompt || body.prompt;
            if (req._prompt !== 'none') return ensureLogin.ensureLoggedIn()(req, res, next);
            next();
        },

        server.authorization(function validate(clientId, redirectURI, scope, done) {
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
        }),

        function (req, res, next) {
            if (req._prompt !== 'none') return next();
            server.decision({loadTransaction: false}, function parse(sreq, done) {
                if (!sreq.user) return done(null, {allow: false});
                done();
            })(req, res, next);
        },

        function (req, res) {
            res.render('dialog', {
                transactionID: req.oauth2.transactionID,
                user: req.user,
                client: req.oauth2.client
            });
        }
    );

    // Authorization Endpoint (POST)
    router.post(config.authorizationEndpoint,
        cors(),
        ensureLogin.ensureLoggedIn(),
        server.decision()
    );

    // Token Endpoint
    router.post(config.tokenEndpoint,
        cors(),
        passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
        server.token(),
        server.errorHandler()
    );

    // UserInfo Endpoint
    router.get(config.userInfoEndpoint,
        passport.authenticate('accessToken', {session: false}),
        function (req, res, next) {
            db.users.findById(req.user.id, function (err, user) {
                if (err) return next(err);
                res.send({
                    'sub': user.id,
                    'name': user.name,
                    'email': user.email
                });
            });
        }
    );

    // Discovery Document
    router.get('/.well-known/openid-configuration', cors(), function (req, res) {
        res.json({
            'issuer': config.baseUrl,
            'authorization_endpoint': config.baseUrl + config.authorizationEndpoint,
            'token_endpoint': config.baseUrl + config.tokenEndpoint,
            'userinfo_endpoint': config.baseUrl + config.userInfoEndpoint,
            'jwks_uri': config.baseUrl + config.jwksUri,
            'response_types_supported': [
                'code',
                'token',
                'id_token',
                'code id_token',
                'token id_token',
                'code id_token token',
                'code token'
            ],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': [config.idTokenAlg],
            'scopes_supported': ['openid'],
            'token_endpoint_auth_methods_supported': [
                'client_secret_post',
                'client_secret_basic'
                //'client_secret_jwt'
            ],
            'claims_supported': ['email', 'name', 'sub']
        });
    });

    // JSON Web Key Set
    router.get(config.jwksUri, cors(), function (req, res) {
        res.json({
            keys: [rsaPemToJwk(config.key, {use: 'sig'}, 'public')]
        });
    });

    return router;
};
