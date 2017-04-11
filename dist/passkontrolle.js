'use strict';

var atob = require('atob'),
    uuid = require('uuidv4');

var passkontrolle = {};

passkontrolle.getToken = function (url) {
  if (!url) {
    throw new Error('Url is missing.');
  }

  var token = void 0;

  try {
    token = url.match(/(#|&)id_token=([^&]+)/)[2];
  } catch (ex) {
    // Intentionally ignore any errors here. If we could not analyse the url,
    // just return without a token.
    return;
  }

  return token;
};

passkontrolle.getPayloadFromToken = function (token) {
  if (!token) {
    throw new Error('Token is missing.');
  }

  var payload = void 0;

  try {
    var bodyBase64Url = token.split('.')[1];

    var bodyBase64 = bodyBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
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

  var identityProviderUrl = options.identityProviderUrl,
      clientId = options.clientId,
      redirectUrl = options.redirectUrl;


  var responseType = ('id_token ' + options.responseType).trim(),
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