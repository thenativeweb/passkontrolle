'use strict';

const assert = require('assertthat'),
      uuid = require('uuidv4');

const passkontrolle = require('../../lib/passkontrolle');

suite('passkontrolle', () => {
  test('is an object.', done => {
    assert.that(passkontrolle).is.ofType('object');
    done();
  });

  suite('getToken', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.getToken).is.ofType('function');
      done();
    });

    test('throws an error if url is missing.', done => {
      assert.that(() => {
        passkontrolle.getToken();
      }).is.throwing('Url is missing.');
      done();
    });

    test('returns the token if a token is given.', done => {
      const url = 'https://www.example.com#id_token=abc';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the token if a token is given as non-first parameter.', done => {
      const url = 'https://www.example.com#foo=bar&id_token=abc&bar=baz';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns the token if only the hash is given.', done => {
      const url = '#id_token=abc';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.equalTo('abc');
      done();
    });

    test('returns undefined if the url does not have a hash.', done => {
      const url = 'https://www.example.com';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the url has an empty hash.', done => {
      const url = 'https://www.example.com#';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.undefined();
      done();
    });

    test('returns undefined if the hash does not contain a token.', done => {
      const url = 'https://www.example.com#foo=bar&bar=baz';
      const token = passkontrolle.getToken(url);

      assert.that(token).is.undefined();
      done();
    });
  });

  suite('getPayloadFromToken', () => {
    test('is a function.', done => {
      assert.that(passkontrolle.getPayloadFromToken).is.ofType('function');
      done();
    });

    test('throws an error if token is missing.', done => {
      assert.that(() => {
        passkontrolle.getPayloadFromToken();
      }).is.throwing('Token is missing.');
      done();
    });

    test('returns the decoded payload from the token.', done => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoZWxsb0B0aGVuYXRpdmV3ZWIuaW8ifQ.wU9GhtuDOYeMsOmV9ID83eDyKezmSIvU3XzjBdnTbRM';
      const payload = passkontrolle.getPayloadFromToken(token);

      assert.that(payload).is.equalTo({
        sub: 'hello@thenativeweb.io'
      });
      done();
    });

    test('returns the decoded payload from the token even if it contains base64url specific characters.', done => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoZWxsb0B0aGVuYXRpdmV3ZWIuaW8iLCJmaXJzdG5hbWUiOiJKYW5lIiwibGFzdG5hbWUiOiJEb2UifQ.dy83xjrt5lQ8-zsDI9kdTWoCUSu7jhb14CSCuvvXIUw';
      const payload = passkontrolle.getPayloadFromToken(token);

      assert.that(payload).is.equalTo({
        sub: 'hello@thenativeweb.io',
        firstname: 'Jane',
        lastname: 'Doe'
      });
      done();
    });

    test('returns undefined if garbage is provided.', done => {
      const token = 'header.body.signature';
      const payload = passkontrolle.getPayloadFromToken(token);

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

      assert.that(authentication.url).is.startingWith('https://auth.example.com?client_id=client-id&redirect_uri=https%3A%2F%2Flocalhost&scope=openid&response_type=id_token%20undefined&nonce=');
      done();
    });
  });
});
