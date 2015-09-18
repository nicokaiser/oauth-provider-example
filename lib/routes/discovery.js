'use strict';

var express = require('express');
var cors = require('cors');

module.exports = function (config) {
    var router = express.Router();

    router.options('/.well-known/openid-configuration', cors(config.cors));
    router.get('/.well-known/openid-configuration', cors(config.cors), function (req, res) {
        res.json({
            'issuer': config.baseUrl,
            'authorization_endpoint': config.baseUrl + config.authorizationEndpoint,
            'token_endpoint': config.baseUrl + config.tokenEndpoint,
            'userinfo_endpoint': config.baseUrl + config.userInfoEndpoint,
            'jwks_uri': config.baseUrl + config.jwksUri,
            'response_types_supported': [
                'code',
                'token',
                'id_token',
                'code id_token',
                'token id_token',
                'code id_token token',
                'code token'
            ],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': [config.idTokenAlg],
            'scopes_supported': ['openid'],
            'token_endpoint_auth_methods_supported': [
                'client_secret_post',
                'client_secret_basic'
            ],
            'claims_supported': ['email', 'name', 'sub']
        });
    });

    return router;
};
