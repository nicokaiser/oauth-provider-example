'use strict';

var fs = require('fs');
var path = require('path');

module.exports = {
    baseUrl: 'http://localhost:3000',

    // Endpoints
    authorizationEndpoint: '/oauth2/auth',
    tokenEndpoint: '/oauth2/token',
    userInfoEndpoint: '/oauth2/userinfo',
    tokenInfoEndpoint: '/oauth2/tokeninfo',
    jwksUri: '/oauth2/certs',

    // Token settings
    idTokenTTL: 3600,
    idTokenAlg: 'RS256',
    accessTokenTTL: 3600,
    authCodeTTL: 600,
    refreshTokenTTL: 7 * 24 * 3600,

    // CORS settings
    cors: {},

    key: fs.readFileSync(path.resolve(__dirname, '../key.pem'))
};
