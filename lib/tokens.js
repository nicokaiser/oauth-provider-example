'use strict';

var jwt = require('jwt-simple');

function Tokens (opts) {
    opts = opts || {};
    if (!opts.type) throw new Error('Token needs a "type" property');
    if (!opts.secret) throw new Error('Token needs a "secret" property');

    this.type = opts.type;
    this.secret = opts.secret;
    this.ttl = opts.ttl;
}

Tokens.prototype.create = function (data, done) {
    var token = {typ: this.type};
    if (this.ttl) token.exp = now() + this.ttl;
    for (var key in data) {
        token[key] = data[key];
    }

    done(null, jwt.encode(token, this.secret));
};

Tokens.prototype.find = function (token, done) {
    var decoded;
    try {
        decoded = jwt.decode(token, this.secret);
    } catch (err) {
        return done(err);
    }

    if (decoded.typ !== this.type) return done(null, false);
    if (token.exp && token.exp < now()) return done(null, false);
    done(null, decoded);
};

function now() {
    return Math.floor(Date.now() / 1000);
}

module.exports = Tokens;
