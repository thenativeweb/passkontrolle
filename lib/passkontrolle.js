'use strict';

const atob = require('atob-lite'),
      uuid = require('uuidv4');

const passkontrolle = {};

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

    const bodyBase64 = bodyBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
          bodyDecoded = atob(bodyBase64);

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
