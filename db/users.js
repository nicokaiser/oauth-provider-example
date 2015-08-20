'use strict';

var users = [
    {
        id: 1,
        username: 'bob',
        password: 'secret',
        name: 'Bob Smith'
    }, {
        id: 2,
        username: 'joe',
        password: 'password',
        name: 'Joe Davis'
    }
];

exports.findById = function (id, done) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.id === id) {
            return done(null, user);
        }
    }
    return done(null, null);
};

exports.findByUsername = function (username, done) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.username === username) {
            return done(null, user);
        }
    }
    return done(null, null);
};

exports.checkCredentials = function (username, password, done) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.username === username) {
            return done(null, (user.password === password));
        }
    }
    return done(null, false);
};
