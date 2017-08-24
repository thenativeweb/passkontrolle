'use strict';

var uuid = require('uuidv4');

var passkontrolle = {};

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

    var bodyBase64 = bodyBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
        bodyDecoded = new Buffer(bodyBase64, 'base64').toString('utf8');

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