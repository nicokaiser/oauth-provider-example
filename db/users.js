'use strict';

var users = [
    { id: '1', username: 'bob', password: '$2a$04$.GqR8TQy78M3N/v1dh9fKul23eQSSa5ChVAnIJlUq43UOJ93597FK' /* 'secret' */, name: 'Bob Smith' },
    { id: '2', username: 'joe', password: '$2a$04$ZqXf8XLhspzQef4aacdQ8ut069esmA7nm5VkrGqEzDV0z8LA9XlQ.' /* 'password' */, name: 'Joe Davis' }
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
