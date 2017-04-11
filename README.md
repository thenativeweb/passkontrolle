# passkontrolle

passkontrolle helps using OpenID Connect.

## Installation

```bash
$ npm install passkontrolle
```

## Quick start

First you need to integrate passkontrolle into your application.

```javascript
const passkontrolle = require('passkontrolle');
```

### Getting a token from a URL

To get a token from a url use the `getToken` function and provide the url as parameter.

```javascript
const token = passkontrolle.getToken('https://www.example.com#id_token=...');
```

If the url does not contain a token, `undefined` is returned.

### Getting the payload from a token

Once you have a token and need to retrieve its payload, use the `getPayloadFromToken` function and provide the token as parameter.

```javascript
const payload = getPayloadFromToken(token);

console.log(payload);
// => {
//      "sub": "hello@thenativeweb.io",
//      ...
//    }
```

If the token is invalid, `undefined` is returned.

### Preparing an authentication request

To prepare an authentication request, use the `prepareAuthentication` function and provide the identity provider's url, the client id, and the redirect url. As a result, you get back an object that contains a `url` and a `nonce`.

```javascript
const authentication = prepareAuthentication({
  identityProviderUrl: 'https://...',
  clientId: '...',
  redirectUrl: 'https://...'
});

console.log(authentication);
// => {
//      url: 'https://...',
//      nonce: '...'
//    }
```

By default, an `id_token` with scope `openid` is requested. To change this, use the optional parameters `responseType` and `scope`. The values you provide are added to the default values, i.e. you never need to specify `id_token` or `openid` manually.

```javascript
const authentication = prepareAuthentication({
  identityProviderUrl: 'https://...',
  clientId: '...',
  redirectUrl: 'https://...',
  responseType: 'token',
  scope: 'profile'
});
```

## Running the build

To build this module use [roboter](https://www.npmjs.com/package/roboter).

```bash
$ bot
```

## License

The MIT License (MIT)
Copyright (c) 2017 the native web.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
