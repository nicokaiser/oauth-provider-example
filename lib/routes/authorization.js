'use strict';

var express = require('express');
var cors = require('cors');
var ensureLogin = require('connect-ensure-login');

var db = require('../../db');

module.exports = function (config, server) {
    var router = express.Router();

    // Authorization Endpoint (GET)
    router.options(config.authorizationEndpoint, cors(config.cors));
    router.get(config.authorizationEndpoint,
        cors(config.cors),
        function (req, res, next) {
            // When using "prompt=none", do not require to be logged in here
            var body = req.body || {};
            req._prompt = req.query.prompt || body.prompt;
            if (req._prompt !== 'none') return ensureLogin.ensureLoggedIn()(req, res, next);
            next();
        },

        server.authorization(function validate(clientId, redirectURI, scope, done) {
            // Check if the client exists and the redirectURI matches to the client's.
            db.clients.findByClientId(clientId, function (err, client) {
                if (err) return done(err);
                if (client && client.redirectURI && (client.redirectURI !== redirectURI)) {
                    return done(new oauth2orize.AuthorizationError(
                        'The redirect_uri MUST match the registered callback URL for this application.',
                        'redirect_uri_mismatch'
                    ));
                }
                return done(null, client, redirectURI);
            });
        }),

        function (req, res, next) {
            if (req._prompt !== 'none') return next();
            // When using "prompt=none", redirect back immediately
            server.decision({loadTransaction: false}, function parse(sreq, done) {
                if (!sreq.user) return done(null, {allow: false});
                done();
            })(req, res, next);
        },

        function (req, res) {
            res.render('dialog', {
                transactionID: req.oauth2.transactionID,
                user: req.user,
                client: req.oauth2.client
            });
        }
    );

    // Authorization Endpoint (POST)
    router.options(config.authorizationEndpoint, cors(config.cors));
    router.post(config.authorizationEndpoint,
        cors(config.cors),
        ensureLogin.ensureLoggedIn(),
        server.decision()
    );

    return router;
};
