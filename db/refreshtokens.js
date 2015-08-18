'use strict';

var tokens = {};

exports.findByRefreshToken = function (token, done) {
    return done(null, tokens[token]);
};

exports.save = function (data, done) {
    tokens[data.refreshToken] = data;
    return done(null);
};
