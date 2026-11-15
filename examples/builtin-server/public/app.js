// The browser half of the example: get a token from Rante, call this app's own API with it.
(function () {
  'use strict';

  var statusLine = document.getElementById('status');
  var result = document.getElementById('result');
  var me = document.getElementById('me');
  var errorLine = document.getElementById('error');
  var appId = document.querySelector('meta[name="rante-app-id"]').content;

  function fail(err) {
    errorLine.hidden = false;
    errorLine.textContent = err && err.code === 'not_in_host'
      ? 'Open this page from My apps in the Rante Portal: it needs Rante around it.'
      : 'Something went wrong: ' + (err && err.message ? err.message : err);
    statusLine.textContent = '';
  }

  Rante.init({ appId: appId, autoResize: true })
    .then(function (host) {
      document.documentElement.dataset.theme = host.theme;
      Rante.on('theme.changed', function (e) { document.documentElement.dataset.theme = e.theme; });
      statusLine.textContent = 'Connected. Asking Rante for an access token...';
      return Rante.getAccessToken();
    })
    .then(function (access) {
      return fetch('/api/me', { headers: { Authorization: 'Bearer ' + access.token } });
    })
    .then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok) {
          var err = new Error(body.message || ('The API answered ' + response.status));
          err.code = body.error;
          throw err;
        }
        return body;
      });
    })
    .then(function (body) {
      statusLine.textContent = 'Signed in as ' + (body.name || body.userId) + '.';
      me.textContent = JSON.stringify(body, null, 2);
      result.hidden = false;
    })
    .catch(fail);
})();
