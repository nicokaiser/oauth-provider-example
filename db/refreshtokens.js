'use strict';

var randomstring = require('randomstring');

exports.ttl = 3600 * 24 * 30;

var memory = {};

exports.create = function (data, done) {
    var token = randomstring.generate(20);
    memory[token] = {
        expires: Date.now() + exports.ttl * 1000,
        payload: data
    };
    done(null, token);
};

exports.get = function (token, done) {
    var value = memory[token];

    // not found
    if (!value) return done(null, false);

    // expired
    if (value.expires <= Date.now()) {
        delete memory[token];
        return done(null, false);
    }

    return done(null, value.payload);
};

exports.remove = function (token, done) {
    delete memory[token];
    return done(null);
};

exports.removeByUserId = function (userId, done) {
    // TODO
    return done(null);
};
