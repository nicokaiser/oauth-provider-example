'use strict';

var jwt = require('jwt-simple');

exports.secret = 'keyboard cat';

exports.create = function (data, done) {
    var token = {
        typ: 'code',
        aud: data.clientId,
        sub: data.userId,
        exp: data.expires,
        redirect: data.redirectURI,
        scope: data.scope
    };
    done(null, jwt.encode(token, exports.secret));
};

exports.get = function (token, done) {
    var data;
    try {
        data = jwt.decode(token, exports.secret);
    } catch (err) {
        return done(err);
    }

    if (data.typ !== 'code') return done(null, false);
    if (token.exp && token.exp < Math.floor(Date.now() / 1000)) return done(null, false);

    done(null, {
        clientId: data.aud,
        userId: data.sub,
        expires: data.exp,
        redirectURI: data.redirect,
        scope: data.scope
    });
};

exports.remove = function (token, done) {
    return done(null);
};
