'use strict';

var passport = require('passport');
var jwt = require('jwt-simple');

function IdTokenStrategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (!verify) throw new Error('IdTokenStrategy requires a verify function');

    this._passReqToCallback = options.passReqToCallback;

    this._key = options.key;
    this._alg = options.alg || 'RS256';

    passport.Strategy.call(this);
    this.name = 'id-token';
    this._verify = verify;
}

IdTokenStrategy.prototype.authenticate = function (req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) return this.fail();

    var idToken;
    if (req.body) idToken = req.body.id_token;
    idToken = idToken || req.query.id_token || req.get('id_token');
    if (!idToken) return this.fail();

    this._verifyIdToken(idToken, self._clientID, function (err, parsedIdToken) {
        if (err) return self.fail(err);
        function verified(err2, parsedToken, info) {
            if (err2) return self.error(err2);
            if (!parsedToken) return self.fail(info);
            self.success(parsedToken, info);
        }

        if (self._passReqToCallback) {
            self._verify(req, parsedIdToken, parsedIdToken.sub, verified);
        } else {
            self._verify(parsedIdToken, parsedIdToken.sub, verified);
        }
    });
};

IdTokenStrategy.prototype._verifyIdToken = function (idToken, clientID, done) {
    var parsedToken;
    try {
        parsedToken = jwt.decode(idToken, this._key, this._alg);
    } catch (e) {
        return done(e);
    }

    if (parsedToken.exp && parsedToken.exp < Math.floor(Date.now() / 1000)) return done(null, false);

    return done(null, parsedToken);
};

module.exports = IdTokenStrategy;
