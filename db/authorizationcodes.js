'use strict';

var codes = {};

exports.findByCode = function (code, done) {
    return done(null, codes[code]);
};

exports.save = function (data, done) {
    codes[data.code] = data;
    return done(null);
};

exports.removeByCode = function (code, done) {
    delete codes[code];
    return done(null);
};
