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

    // ID Token
    idTokenTTL: 3600,
    idTokenAlgorithm: 'RS256',
    idTokenSecret: fs.readFileSync(path.resolve(__dirname, '../key.pem')),

    // Access Token
    accessTokenTTL: 3600,
    accessTokenAlgorithm: 'HS256',
    accessTokenSecret: 'keyboard cat2',

    // Refresh Token
    refreshTokenTTL: 3600 * 24 * 30,

    // Auth Code
    authCodeTTL: 600, // 10

    // CORS settings
    cors: {}
};
