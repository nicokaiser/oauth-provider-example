'use strict';

var tokens = {};

exports.findByToken = function (token, done) {
    return done(null, tokens[token]);
};

exports.save = function (data, done) {
    tokens[data.token] = data;
    return done(null);
};

exports.updateByUserId = function (userId, data, done) {
    for (var i = 0, len = tokens.length; i < len; i++) {
        var token = tokens[i];
        if (token.userId === userId) {
            delete(tokens[token]);
            tokens[data.token] = data;
            return done(null);
        }
    }
    return done(null);
};

exports.removeByToken = function (token, done) {
    delete tokens[token];
    return done(null);
};
