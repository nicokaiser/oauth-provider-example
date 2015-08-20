'use strict';

var clients = [
    {
        clientId: 'client1',
        clientSecret: 'secret1',
        name: 'Client 1',
        trusted: true

    }, {
        clientId: 'oauth-consumer-example',
        clientSecret: 'secret2',
        name: 'OAuth Consumer Example Client',
        redirectURI: 'http://localhost:3002/auth/example',
        trusted: true
    }, {
        clientId: 'google-playground',
        clientSecret: 'foo',
        name: 'Google OAuth 2.0 Playground',
        redirectURI: 'https://developers.google.com/oauthplayground/',
        trusted: true
    }
];

exports.findByClientId = function (clientId, done) {
    for (var i = 0, len = clients.length; i < len; i++) {
        var client = clients[i];
        if (client.clientId === clientId) {
            return done(null, client);
        }
    }
    return done(null, null);
};
