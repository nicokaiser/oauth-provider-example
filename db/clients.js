'use strict';

var clients = [
    { clientId: 'client1', name: 'Client 1', clientSecret: 'secret1' },
    { clientId: 'client2', name: 'Client 2', clientSecret: 'secret2' }
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
