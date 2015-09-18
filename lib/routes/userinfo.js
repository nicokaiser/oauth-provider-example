'use strict';

var express = require('express');
var cors = require('cors');
var passport = require('passport');
var db = require('../../db');

module.exports = function (config) {
    var router = express.Router();

    router.options(config.userInfoEndpoint, cors(config.cors));
    router.get(config.userInfoEndpoint,
        cors(config.cors),
        passport.authenticate('accessToken', {session: false}),

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
