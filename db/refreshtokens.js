'use strict';

var jwt = require('jsonwebtoken');

exports.secret = 'keyboard cat';
exports.algorithm = 'HS256';
exports.ttl = 3600 * 24 * 30;

exports.create = function (data, done) {
    var token = jwt.sign({
        aud: data.clientId,
        sub: data.userId,
        scope: data.scope
    }, exports.secret, {
        algorithm: exports.algorithm,
        expiresInSeconds: exports.ttl
    });
    done(null, token);
};

exports.get = function (token, done) {
    jwt.verify(token, exports.secret, function (err, decoded) {
        if (err) return done(null, false);
        done(null, {
            clientId: decoded.aud,
            userId: decoded.sub,
            scope: decoded.scope
        });
    });
};

exports.remove = function (token, done) {
    // not applicable with JWT refresh tokens
    return done(null);
};

exports.removeByUserId = function (userId, done) {
    // not applicable with JWT refresh tokens
    return done(null);
};
