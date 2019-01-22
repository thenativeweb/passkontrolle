'use strict';

const assert = require('assertthat'),
      uuid = require('uuidv4');

const passkontrolle = require('../../src/passkontrolle');

suite('passkontrolle', () => {
  test('is an object.', done => {
    assert.that(passkontrolle).is.ofType('object');
    done();
  });

  suite('getIdToken', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.getIdToken).is.ofType('function');
      done();
    });

    test('throws an error if url is missing.', done => {
      assert.that(() => {
        passkontrolle.getIdToken();
      }).is.throwing('Url is missing.');
      done();
    });

    test('returns the id token if an id token is given.', done => {
      const url = 'https://www.example.com#id_token=abc';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the id token if an id token is given as non-first parameter.', done => {
      const url = 'https://www.example.com#foo=bar&id_token=abc&bar=baz';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the id token if an id token and an access token are given.', done => {
      const url = 'https://www.example.com#foo=bar&id_token=abc&token=def&bar=baz';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the id token if only the hash is given.', done => {
      const url = '#id_token=abc';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns undefined if the url does not have a hash.', done => {
      const url = 'https://www.example.com';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the url has an empty hash.', done => {
      const url = 'https://www.example.com#';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the hash does not contain an id token.', done => {
      const url = 'https://www.example.com#foo=bar&bar=baz';
      const token = passkontrolle.getIdToken(url);

      assert.that(token).is.undefined();
      done();
    });
  });

  suite('getAccessToken', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.getAccessToken).is.ofType('function');
      done();
    });

    test('throws an error if url is missing.', done => {
      assert.that(() => {
        passkontrolle.getAccessToken();
      }).is.throwing('Url is missing.');
      done();
    });

    test('returns the access token if an access token is given.', done => {
      const url = 'https://www.example.com#access_token=abc';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the access token if an access token is given as non-first parameter.', done => {
      const url = 'https://www.example.com#foo=bar&access_token=abc&bar=baz';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the access token if an id token and an access token are given.', done => {
      const url = 'https://www.example.com#foo=bar&access_token=abc&id_token=def&bar=baz';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the access token if only the hash is given.', done => {
      const url = '#access_token=abc';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns undefined if the url does not have a hash.', done => {
      const url = 'https://www.example.com';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the url has an empty hash.', done => {
      const url = 'https://www.example.com#';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the hash does not contain a token.', done => {
      const url = 'https://www.example.com#foo=bar&bar=baz';
      const token = passkontrolle.getAccessToken(url);

      assert.that(token).is.undefined();
      done();
    });
  });

  suite('getPayloadFromIdToken', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.getPayloadFromIdToken).is.ofType('function');
      done();
    });

    test('throws an error if token is missing.', done => {
      assert.that(() => {
        passkontrolle.getPayloadFromIdToken();
      }).is.throwing('Id token is missing.');
      done();
    });

    test('returns the decoded payload from the token.', done => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoZWxsb0B0aGVuYXRpdmV3ZWIuaW8ifQ.wU9GhtuDOYeMsOmV9ID83eDyKezmSIvU3XzjBdnTbRM';
      const payload = passkontrolle.getPayloadFromIdToken(token);

      assert.that(payload).is.equalTo({
        sub: 'hello@thenativeweb.io'
      });
      done();
    });

    test('returns the decoded payload from the token even if it contains base64url specific characters.', done => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoZWxsb0B0aGVuYXRpdmV3ZWIuaW8iLCJmaXJzdG5hbWUiOiJKYW5lIiwibGFzdG5hbWUiOiJEb2UifQ.dy83xjrt5lQ8-zsDI9kdTWoCUSu7jhb14CSCuvvXIUw';
      const payload = passkontrolle.getPayloadFromIdToken(token);

      assert.that(payload).is.equalTo({
        sub: 'hello@thenativeweb.io',
        firstname: 'Jane',
        lastname: 'Doe'
      });
      done();
    });

    test('returns the decoded payload from the token even if the token contains unicode characters.', done => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoZWxsb0B0aGVuYXRpdmV3ZWIuaW8iLCJmaXJzdG5hbWUiOiLtlZzquIAiLCJsYXN0bmFtZSI6IuyhsOyEoOq4gCJ9.eFNgoIWMajuHwF2HRRangBABokgR2CshBUb_7IiaZr8';
      const payload = passkontrolle.getPayloadFromIdToken(token);

      assert.that(payload).is.equalTo({
        sub: 'hello@thenativeweb.io',
        firstname: '한글',
        lastname: '조선글'
      });
      done();
    });

    test('returns undefined if garbage is provided.', done => {
      const token = 'header.body.signature';
      const payload = passkontrolle.getPayloadFromIdToken(token);

      assert.that(payload).is.undefined();
      done();
    });
  });

  suite('prepareAuthentication', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.prepareAuthentication).is.ofType('function');
      done();
    });

    test('throws an error if options are missing.', done => {
      assert.that(() => {
        passkontrolle.prepareAuthentication();
      }).is.throwing('Options are missing.');
      done();
    });

    test('throws an error if identity provider url is missing.', done => {
      assert.that(() => {
        passkontrolle.prepareAuthentication({});
      }).is.throwing('Identity provider url is missing.');
      done();
    });

    test('throws an error if client id is missing.', done => {
      assert.that(() => {
        passkontrolle.prepareAuthentication({ identityProviderUrl: 'https://auth.example.com' });
      }).is.throwing('Client id is missing.');
      done();
    });

    test('throws an error if redirect url is missing.', done => {
      assert.that(() => {
        passkontrolle.prepareAuthentication({ identityProviderUrl: 'https://auth.example.com', clientId: 'client-id' });
      }).is.throwing('Redirect url is missing.');
      done();
    });

    test('returns an object.', done => {
      const authentication = passkontrolle.prepareAuthentication({
        identityProviderUrl: 'https://auth.example.com',
        clientId: 'client-id',
        redirectUrl: 'https://localhost'
      });

      assert.that(authentication).is.ofType('object');
      done();
    });

    test('returns a nonce.', done => {
      const authentication = passkontrolle.prepareAuthentication({
        identityProviderUrl: 'https://auth.example.com',
        clientId: 'client-id',
        redirectUrl: 'https://localhost'
      });

      assert.that(uuid.is(authentication.nonce)).is.true();
      done();
    });

    test('returns a new nonce every time.', done => {
      const nonce1 = passkontrolle.prepareAuthentication({
        identityProviderUrl: 'https://auth.example.com',
        clientId: 'client-id',
        redirectUrl: 'https://localhost'
      }).nonce;

      const nonce2 = passkontrolle.prepareAuthentication({
        identityProviderUrl: 'https://auth.example.com',
        clientId: 'client-id',
        redirectUrl: 'https://localhost'
      }).nonce;

      assert.that(nonce1).is.not.equalTo(nonce2);
      done();
    });

    test('returns a url.', done => {
      const authentication = passkontrolle.prepareAuthentication({
        identityProviderUrl: 'https://auth.example.com',
        clientId: 'client-id',
        redirectUrl: 'https://localhost'
      });

      assert.that(authentication.url).is.startingWith('https://auth.example.com?client_id=client-id&redirect_uri=https%3A%2F%2Flocalhost&scope=openid&response_type=id_token&nonce=');
      done();
    });
  });
});
