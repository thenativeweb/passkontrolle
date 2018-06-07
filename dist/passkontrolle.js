'use strict';

/* global window */

var uuid = require('uuidv4');

var passkontrolle = {};

var decodeBase64 = function decodeBase64(encoded) {
  if (!encoded) {
    throw new Error('Encoded string is missing.');
  }

  if (typeof Buffer !== 'undefined') {
    var _decoded = new Buffer(encoded, 'base64').toString('utf8');

    return _decoded;
  }

  // Inspired by https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
  var decodedCharacters = window.atob(encoded).split('');

  var urlEncodedCharCodes = decodedCharacters.map(function (decodedCharacter) {
    var urlEncodedCharCode = ('00' + decodedCharacter.charCodeAt(0).toString(16)).slice(-2);

    return '%' + urlEncodedCharCode;
  });

  var decoded = decodeURIComponent(urlEncodedCharCodes).join('');

  return decoded;
};

passkontrolle.getToken = function (url, regex) {
  if (!url) {
    throw new Error('Url is missing.');
  }
  if (!regex) {
    throw new Error('Regular expression is missing.');
  }

  var token = void 0;

  try {
    token = url.match(regex)[2];
  } catch (ex) {
    // Intentionally ignore any errors here. If we could not analyse the url,
    // just return without a token.
    return;
  }

  return token;
};

passkontrolle.getIdToken = function (url) {
  if (!url) {
    throw new Error('Url is missing.');
  }

  return this.getToken(url, /(#|&)id_token=([^&]+)/);
};

passkontrolle.getAccessToken = function (url) {
  if (!url) {
    throw new Error('Url is missing.');
  }

  return this.getToken(url, /(#|&)access_token=([^&]+)/);
};

passkontrolle.getPayloadFromIdToken = function (token) {
  if (!token) {
    throw new Error('Id token is missing.');
  }

  var payload = void 0;

  try {
    var bodyBase64Url = token.split('.')[1];

    // Using Buffer here is not optimal if you use this module with a bundler
    // such as webpack. Actually, we used atob-lite before, but this caused
    // problems with unicode characters in the token's payload. Hence we
    // decided to go with Buffer, as this works flawlessly.
    var bodyBase64 = bodyBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
        bodyDecoded = decodeBase64(bodyBase64);

    payload = JSON.parse(bodyDecoded);
  } catch (ex) {
    // Intentionally ignore any errors here. If we could not decode the token,
    // just return without a payload.
    return;
  }

  return payload;
};

passkontrolle.prepareAuthentication = function (options) {
  if (!options) {
    throw new Error('Options are missing.');
  }
  if (!options.identityProviderUrl) {
    throw new Error('Identity provider url is missing.');
  }
  if (!options.clientId) {
    throw new Error('Client id is missing.');
  }
  if (!options.redirectUrl) {
    throw new Error('Redirect url is missing.');
  }

  var identityProviderUrl = options.identityProviderUrl,
      clientId = options.clientId,
      redirectUrl = options.redirectUrl;


  var responseType = ('id_token ' + (options.responseType || '')).trim(),
      scope = ('openid ' + (options.scope || '')).trim();

  var clientIdEncoded = encodeURIComponent(clientId),
      redirectUrlEncoded = encodeURIComponent(redirectUrl),
      responseTypeEncoded = encodeURIComponent(responseType),
      scopeEncoded = encodeURIComponent(scope);

  var nonce = uuid();
  var url = identityProviderUrl + '?client_id=' + clientIdEncoded + '&redirect_uri=' + redirectUrlEncoded + '&scope=' + scopeEncoded + '&response_type=' + responseTypeEncoded + '&nonce=' + nonce;

  return {
    url: url,
    nonce: nonce
  };
};

module.exports = passkontrolle;