'use strict';

var express = require('express');
var cors = require('cors');
var passport = require('passport');

module.exports = function (config, server) {
    var router = express.Router();

    router.options(config.tokenEndpoint, cors(config.cors));
    router.post(config.tokenEndpoint,
        cors(config.cors),
        passport.authenticate(['basic', 'oauth2-client-password', 'oauth2-resource-owner-password'], {session: false}),
        server.token(),
        server.errorHandler()
    );

    return router;
};
