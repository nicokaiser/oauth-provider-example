OAuth 2.0 Provider Example
==========================

A simple OAuth 2.0 provider example that uses [oauth2orize](https://github.com/jaredhanson/oauth2orize), [Passport](http://passportjs.org/) and [Express](http://expressjs.com/) and implements several OAuth 2.0 flows.

Note that this is only an example, in production systems you probably want to use proper databases and HTTPS.


Usage
-----

```
$ npm install
$ node app.js
```

An example consumer can be found at [oauth-consumer-example](https://github.com/nicokaiser/oauth-consumer-example).


Authorization
-------------

There are several "flows" available for obtaining access tokens.

### Authorization Code Grant

The authorization code grant flow is typically used for web server applications. The client_secret is known to the server-side application. See https://tools.ietf.org/html/rfc6749#section-4.1.


#### Authorization Request

```
http://localhost:3000/oauth2/auth?response_type=code&client_id=client1&state=xyz&redirect_uri=http://api.example.com/cb
```

Once the use is logged in (try "bob", "secret" in this example), the authorization dialog is displayed ("Client 1 is requesting access to your account."). After pressing "Allow", the user is redirected to the `redirect_uri` with a `code` parameter:

```
HTTP/1.1 302 Found
Location: http://api.example.com/cb?code=fCUHnidI4tOidJLS&state=xyz
```

If pressing "Deny", an `error` parameter is added to the `redirect_uri`:

```
HTTP/1.1 302 Found
Location: http://api.example.com/cb?error=access_denied&state=xyz
```

#### Access Token Request

The web server application can request access tokens and refres tokens in the background by using the code:

```
$ curl -d "grant_type=authorization_code&code=fCUHnidI4tOidJLS&client_id=client1&client_secret=secret1&redirect_uri=http://api.example.com/cb" http://localhost:3000/oauth2/token
```

```
{
    "access_token":"vBmly...",
    "refresh_token":"kjzpM...",
    "expires_in":3600,
    "token_type":"Bearer"
}
```

#### Refreshing an Access Token

```
$ curl -u client1:secret1 -d "grant_type=refresh_token&refresh_token=wlvX9..." http://localhost:3000/oauth2/token
```

```
{
    "access_token":"rlM7p...",
    "refresh_token":"01Lo4...",
    "expires_in":3600,
    "token_type":"Bearer"
}
```


### Implicit Grant

The implicit grant type is used for web applications running in a browser (e.g. JavaScript applications). No client secret is stored in the client. See https://tools.ietf.org/html/rfc6749#section-4.2


#### Authorization Request

```
http://localhost:3000/oauth2/auth?response_type=token&client_id=client1&state=xyz&redirect_uri=http://api.example.com/cb
```

After pressing "Allow", the user is redirected to the `redirect_uri` with the access token data in the URL hash:

```
HTTP/1.1 302 Found
Location: http://api.example.com/cb#access_token=6iYAL...&expires_in=2015-08-18T09%3A12%3A11.282Z&token_type=Bearer&state=xyz
```

In case of an error (e.g. the user denied access), the error code is added to the URL hash:

```
HTTP/1.1 302 Found
Location: http://api.example.com/cb#error=access_denied&state=xyz
```


### Resource Owner Password Credentials Grant

This grant type is used for trusted clients grants access tokens for credentials (username, password). No client_secret is transmitted. See https://tools.ietf.org/html/rfc6749#section-4.3


#### Authorization Request

```
$ curl -d "grant_type=password&client_id=client1&client_secret=secret1&username=bob&password=secret" http://localhost:3000/oauth2/token
```

```
{
    "access_token":"SDXfE...",
    "refresh_token":"sgxHw...",
    "expires_in":3600,
    "token_type":"Bearer"
}
```

### Client Credentials Grant

The client (e.g. an application) needs to request an access token by using only its client credentials (client_id, client_secret), this grant type is used. The client_secret is stored in the client. See https://tools.ietf.org/html/rfc6749#section-4.4


#### Authorization Request

```
$ curl -d "grant_type=client_credentials&client_id=client1&client_secret=secret1" http://localhost:3000/oauth2/token
```

```
{
    "access_token":"oRoId...",
    "expires_in":3600,
    "token_type":"Bearer"
}
```


Accessing the Protected Resource
--------------------------------

The access token can now be used to get access to the protected resource, in this example the `/restricted` URI:

```
$ curl -H "Authorization: Bearer MEwck..." http://localhost:3000/time
$ curl http://localhost:3000/time?access_token=MEwck...
```


Todo
----
- Do we really need client_secret in grant_type=refresh_token?
- Do we really need client_secret in grant_type=password?
- Implement trusted clients that need no dialog (immediate decision?)


Credits
-------

- https://github.com/reneweb/
- https://github.com/jaredhanson/oauth2orize/
- https://tools.ietf.org/html/rfc6749


License
-------

MIT
