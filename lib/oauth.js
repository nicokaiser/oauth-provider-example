'use strict';

var oauth2orize = require('oauth2orize');
var oauth2orizeOpenid = require('oauth2orize-openid');
var ensureLogin = require('connect-ensure-login');
var jwt = require('jwt-simple');
var passport = require('passport');
var debug = require('debug')('oauth-provider');

var db = require('../db');

var config = {
    issuer: 'http://localhost:3000',
    idTokenSecret: 'myidtokensecret',
    idTokenTTL: 3600,
    idTokenAlg: 'HS256',
    accessTokenTTL: 3600,
    authCodeTTL: 600
};

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


// OpenID Connect 1.0 grant types

// Implicit Flow: 'id_token' grant type
server.grant(oauth2orizeOpenid.grant.idToken(function (client, user, done) {
    debug('OpenID Connect: "id_token" grant');
    createIdToken(client, user, done);
}));

// Implicit Flow: 'id_token token' grant type
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

// Hybrid Flow: 'code id_token' grant type
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

// Hybrid Flow: 'code token' grant type.
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

// Hybrid Flow: 'code id_token token' grant type.
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

// Authorization Code Flow: 'code' grant type
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

// Authorization Code Flow: exchange code => access_token + refresh_token
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

// Authorization Code Flow: exchange refresh_token => access_token
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

// Implicit Flow: 'token' grant type
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

// Client Credentials Flow: exchange clientId, clientSecret => access_token
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

// Resource Owner Password Flow: exchange username, password => access_token
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

// Authorization Endpoint (GET)
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

// Authorization Endpoint (POST)
exports.decision = [
    ensureLogin.ensureLoggedIn(),
    server.decision()
];

// Token Endpoint
exports.token = [
    passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
    server.token(),
    server.errorHandler()
];

// UserInfo Endpoint
exports.userinfo = [
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
];

// Discovery Document
exports.discovery = function (req, res) {
    res.json({
        'issuer': 'http://localhost:3000', // REQUIRED
        'authorization_endpoint': 'http://localhost:3000/oauth2/auth', // REQUIRED
        'token_endpoint': 'http://localhost:3000/oauth2/token', // REQUIRED
        'userinfo_endpoint': 'http://localhost:3000/oauth2/userinfo', // RECOMMENDED
        'jwks_uri': '', // TODO  REQUIRED
        'response_types_supported': [ // REQUIRED
            'code', // REQUIRED
            'token',
            'id_token', // REQUIRED
            'code id_token',
            'token id_token', // REQUIRED
            'code token id_token'
            //'none'
        ],
        'subject_types_supported': [ // REQUIRED
            'public'
        ],
        'id_token_signing_alg_values_supported': [ // RECOMMENDED
            config.idTokenAlg
        ],
        'scopes_supported': [ // RECOMMENDED
            'openid' // REQUIRED
        ],
        'token_endpoint_auth_methods_supported': [ // OPTIONAL
            'client_secret_post',
            'client_secret_basic'
            //'client_secret_jwt'
        ],
        'claims_supported': [ // RECOMMENDED
            //'aud',
            'email',
            //'exp',
            //'family_name',
            //'given_name',
            //'nickname',
            //'iat',
            //'iss',
            'name',
            //'picture',
            'sub'
        ]
    });
};


function createIdToken(client, user, done) {
    done(null, jwt.encode({
        'iss': config.issuer,
        'sub': user.id,
        'aud': client.clientId,
        'exp': now() + config.idTokenTTL,
        'iat': now(),
        'auth_time': now()
    }, config.idTokenSecret, config.idTokenAlg));
}


function now() {
    return Math.floor(Date.now() / 1000);
}
