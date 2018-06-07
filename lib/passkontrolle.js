'use strict';

/* global window */

const uuid = require('uuidv4');

const passkontrolle = {};

const decodeBase64 = function (encoded) {
  if (!encoded) {
    throw new Error('Encoded string is missing.');
  }

  if (typeof Buffer !== 'undefined') {
    const decoded = new Buffer(encoded, 'base64').toString('utf8');

    return decoded;
  }

  // Inspired by https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
  const decodedCharacters = window.atob(encoded).split('');

  const urlEncodedCharCodes = decodedCharacters.map(decodedCharacter => {
    const urlEncodedCharCode = `00${decodedCharacter.charCodeAt(0).toString(16)}`.slice(-2);

    return `%${urlEncodedCharCode}`;
  });

  const decoded = decodeURIComponent(urlEncodedCharCodes).join('');

  return decoded;
};

passkontrolle.getToken = function (url, regex) {
  if (!url) {
    throw new Error('Url is missing.');
  }
  if (!regex) {
    throw new Error('Regular expression is missing.');
  }

  let token;

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

  let payload;

  try {
    const bodyBase64Url = token.split('.')[1];

    // Using Buffer here is not optimal if you use this module with a bundler
    // such as webpack. Actually, we used atob-lite before, but this caused
    // problems with unicode characters in the token's payload. Hence we
    // decided to go with Buffer, as this works flawlessly.
    const bodyBase64 = bodyBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
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

  const { identityProviderUrl, clientId, redirectUrl } = options;

  const responseType = `id_token ${options.responseType || ''}`.trim(),
        scope = `openid ${options.scope || ''}`.trim();

  const clientIdEncoded = encodeURIComponent(clientId),
        redirectUrlEncoded = encodeURIComponent(redirectUrl),
        responseTypeEncoded = encodeURIComponent(responseType),
        scopeEncoded = encodeURIComponent(scope);

  const nonce = uuid();
  const url = `${identityProviderUrl}?client_id=${clientIdEncoded}&redirect_uri=${redirectUrlEncoded}&scope=${scopeEncoded}&response_type=${responseTypeEncoded}&nonce=${nonce}`;

  return {
    url,
    nonce
  };
};

module.exports = passkontrolle;
