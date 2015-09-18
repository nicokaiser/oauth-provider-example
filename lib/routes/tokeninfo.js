'use strict';

var express = require('express');
var cors = require('cors');
var passport = require('passport');
var IdTokenStrategy = require('../strategies/id-token');

var db = require('../../db');

module.exports = function (config) {
    passport.use(new IdTokenStrategy({
        key: config.key,
        alg: config.idTokenAlg
    }, function (parsedToken, userId, done) {
        db.users.findById(userId, done);
    }));

    var router = express.Router();

    router.options(config.tokenInfoEndpoint, cors(config.cors));
    router.post(config.tokenInfoEndpoint,
        cors(config.cors),
        passport.authenticate('id-token', {session: false}),

        function (req, res, next) {
            db.users.findById(req.user.id, function (err, user) {
                if (err) return next(err);
                res.send({
                    'user_id': user.id,
                    'name': user.name,
                    'email': user.email
                });
            });
        }
    );

    return router;
};
