'use strict';

var passport = require('passport');
var jwt = require('jsonwebtoken');

function IdTokenStrategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (!verify) throw new Error('IdTokenStrategy requires a verify function');

    this._passReqToCallback = options.passReqToCallback;

    this._secret = options.secret;
    this._algorithm = options.algorithm || 'RS256';

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
    jwt.verify(idToken, this._secret, function (err, decoded) {
        if (err) return done(err);
        // TODO: check clientID ?
        return done(null, decoded);
    });
};

module.exports = IdTokenStrategy;
