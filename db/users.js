'use strict';

var users = [
    {
        id: 1,
        email: 'bob@example.com',
        name: 'Bob Smith',
        password: 'secret'
    }, {
        id: 2,
        email: 'joe@example.com',
        name: 'Joe Davis',
        password: 'password'
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

exports.findByUsername = function (email, done) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.email === email) {
            return done(null, user);
        }
    }
    return done(null, null);
};

exports.checkCredentials = function (username, password, done) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.email === username) {
            if (!user.password === password) return done(null, false);
            return done(null, user);
        }
    }
    return done(null, false);
};
