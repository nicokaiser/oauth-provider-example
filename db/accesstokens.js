'use strict';

var jwt = require('jsonwebtoken');

exports.secret = 'keyboard cat';
exports.algorithm = 'HS256';
exports.ttl = 3600;

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
