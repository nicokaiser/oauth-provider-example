'use strict';

var express = require('express');
var cors = require('cors');
var rsaPemToJwk = require('rsa-pem-to-jwk');

module.exports = function (config) {
    var router = express.Router();

    router.options(config.jwksUri, cors(config.cors));
    router.get(config.jwksUri, cors(config.cors), function (req, res) {
        res.json({
            keys: [rsaPemToJwk(config.key, {use: 'sig'}, 'public')]
        });
    });

    return router;
};
