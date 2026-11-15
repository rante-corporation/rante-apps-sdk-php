/*! Rante Apps SDK 0.1.0 - https://github.com/rante-corporation/rante-apps-sdk - MIT License
 * Talks to the Rante host page from inside an app's iframe, over postMessage and a private MessageChannel.
 * Plain ES2019, no dependencies, no build step. Protocol: docs/protocol.md.
 *
 *   const host = await Rante.init();              // connect to Rante (portal.rante.com)
 *   const user = await Rante.getUser();            // needs the "user.read" permission
 *   const tenant = await Rante.getTenant();        // needs "tenant.read"
 *   const { token } = await Rante.getAccessToken(); // needs "auth.token": send it to your API
 *   Rante.on('theme.changed', (e) => applyTheme(e.theme));
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  var hasWindow = !!(root && root.document && typeof root.addEventListener === 'function');
  var instance = hasWindow ? api.create(root) : api.createUnavailable();
  instance.create = api.create;
  instance.version = api.version;
  instance.PROTOCOL_VERSION = api.PROTOCOL_VERSION;
  instance.RanteError = api.RanteError;
  instance.internals = api.internals;
  if (typeof module === 'object' && module && module.exports) {
    module.exports = instance;
  }
  if (hasWindow && !root.Rante) {
    root.Rante = instance;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '0.1.0';
  var PROTOCOL_VERSION = 1;
  var DEFAULT_HOST_ORIGINS = ['https://portal.rante.com'];
  var HELLO_INTERVAL_MS = 250;
  var DEFAULT_CONNECT_TIMEOUT_MS = 10000;
  var DEFAULT_REQUEST_TIMEOUT_MS = 15000;
  var TOKEN_REQUEST_TIMEOUT_MS = 60000;
  var TOKEN_REFRESH_MARGIN_MS = 60000;
  var METHOD_NAME = /^[a-z][a-zA-Z]*(\.[a-z][a-zA-Z]*)+$/;
  var HOST_ORIGIN = /^https:\/\/[a-z0-9.-]+(:\d{1,5})?$/;
  var DEV_HOST_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;
  var NOTIFICATION_KINDS = ['info', 'success', 'warning', 'error'];

  class RanteError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'RanteError';
      this.code = code;
    }
  }

  function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function stringArray(value) {
    if (!Array.isArray(value)) return [];
    var out = [];
    for (var i = 0; i < value.length; i++) {
      if (typeof value[i] === 'string' && out.indexOf(value[i]) < 0) out.push(value[i]);
    }
    return out;
  }

  function text(value, max) {
    return typeof value === 'string' ? value.slice(0, max) : undefined;
  }

  function randomId(win) {
    var bytes = new Uint8Array(16);
    var cryptoApi = win && win.crypto;
    if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
      cryptoApi.getRandomValues(bytes);
    } else {
      for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    var hex = '';
    for (var j = 0; j < bytes.length; j++) hex += (bytes[j] < 16 ? '0' : '') + bytes[j].toString(16);
    return hex;
  }

  function normalizeHostOrigins(origins) {
    if (origins === undefined) return DEFAULT_HOST_ORIGINS.slice();
    if (!Array.isArray(origins) || origins.length === 0) {
      throw new RanteError('invalid_request', 'hostOrigins must be a non-empty array of origins.');
    }
    var out = [];
    for (var i = 0; i < origins.length; i++) {
      var o = origins[i];
      if (typeof o !== 'string' || !(HOST_ORIGIN.test(o) || DEV_HOST_ORIGIN.test(o))) {
        throw new RanteError('invalid_request', 'Not a host origin: ' + String(o) +
          '. Use https://host[:port] (or http://localhost:port while developing).');
      }
      if (out.indexOf(o) < 0) out.push(o);
    }
    return out;
  }

  /** Reads the connect message into a plain, well-typed object. */
  function readConnectInfo(data) {
    var host = isObject(data.host) ? data.host : {};
    var app = isObject(data.app) ? data.app : {};
    return {
      protocol: typeof data.protocol === 'number' ? data.protocol : PROTOCOL_VERSION,
      host: { name: text(host.name, 50) || 'rante', version: text(host.version, 50) },
      app: { id: text(app.id, 64), version: text(app.version, 64) },
      permissions: stringArray(data.permissions),
      capabilities: stringArray(data.capabilities),
      locale: text(data.locale, 35) || 'en-US',
      theme: data.theme === 'dark' ? 'dark' : 'light'
    };
  }

  function toError(error) {
    if (!isObject(error)) return new RanteError('host_error', 'The Rante host returned an error.');
    return new RanteError(text(error.code, 50) || 'host_error', text(error.message, 500) || 'The Rante host returned an error.');
  }

  function documentHeight(win) {
    var doc = win.document;
    if (!doc || !doc.documentElement) return 0;
    var el = doc.documentElement;
    var body = doc.body;
    return Math.ceil(Math.max(el.scrollHeight || 0, el.offsetHeight || 0, body ? body.scrollHeight || 0 : 0));
  }

  /**
   * Creates an SDK client bound to a window. In a browser the global `Rante` is already such a client; create() exists
   * for tests and for unusual set-ups.
   */
  function create(win) {
    var state = {
      status: 'idle',          // idle -> connecting -> connected | failed
      initPromise: null,
      port: null,
      info: null,
      hostOrigin: null,
      nextId: 1,
      pending: {},
      listeners: {},
      tokenCache: null,
      resize: null
    };

    function emit(event, data) {
      var list = state.listeners[event];
      if (!list) return;
      list.slice().forEach(function (handler) {
        try {
          handler(data);
        } catch (err) {
          if (win.console && typeof win.console.error === 'function') win.console.error(err);
        }
      });
    }

    function onPortMessage(event) {
      var msg = event && event.data;
      if (!isObject(msg)) return;
      if (typeof msg.id === 'number') {
        var pending = state.pending[msg.id];
        if (!pending) return;
        delete state.pending[msg.id];
        win.clearTimeout(pending.timer);
        if (msg.error !== undefined) pending.reject(toError(msg.error));
        else pending.resolve(msg.result === undefined ? {} : msg.result);
        return;
      }
      if (typeof msg.event === 'string') {
        if (msg.event === 'theme.changed' && isObject(msg.data) && state.info) {
          state.info.theme = msg.data.theme === 'dark' ? 'dark' : 'light';
        }
        emit(msg.event, isObject(msg.data) ? msg.data : {});
      }
    }

    function init(options) {
      if (state.initPromise) return state.initPromise;
      options = options || {};
      var hostOrigins;
      try {
        hostOrigins = normalizeHostOrigins(options.hostOrigins);
      } catch (err) {
        return Promise.reject(err);
      }
      if (!win.parent || win.parent === win) {
        return Promise.reject(new RanteError('not_in_host',
          'This page is not running inside Rante. Open the app from My apps in the Rante Portal.'));
      }
      var timeoutMs = typeof options.timeoutMs === 'number' && options.timeoutMs > 0 ? options.timeoutMs : DEFAULT_CONNECT_TIMEOUT_MS;
      var nonce = randomId(win);
      state.status = 'connecting';

      state.initPromise = new Promise(function (resolve, reject) {
        var helloTimer = null;
        var timeoutTimer = null;

        function cleanup() {
          win.removeEventListener('message', onMessage);
          if (helloTimer !== null) win.clearInterval(helloTimer);
          if (timeoutTimer !== null) win.clearTimeout(timeoutTimer);
        }

        function onMessage(event) {
          if (!event || event.source !== win.parent) return;
          if (hostOrigins.indexOf(event.origin) < 0) return;
          var data = event.data;
          if (!isObject(data) || data.rante !== PROTOCOL_VERSION || data.type !== 'connect' || data.nonce !== nonce) return;
          var port = event.ports && event.ports[0];
          if (!port) return;
          cleanup();
          state.port = port;
          state.hostOrigin = event.origin;
          state.info = readConnectInfo(data);
          state.status = 'connected';
          port.onmessage = onPortMessage;
          if (options.ready !== false) {
            request('frame.ready', {}).catch(function () {});
          }
          if (options.autoResize) startAutoResize();
          resolve(getHostInfo());
        }

        function sayHello() {
          var hello = { rante: PROTOCOL_VERSION, type: 'hello', sdk: VERSION, nonce: nonce };
          if (typeof options.appId === 'string') hello.appId = options.appId;
          for (var i = 0; i < hostOrigins.length; i++) {
            try {
              win.parent.postMessage(hello, hostOrigins[i]);
            } catch (err) {
              // A parent on another origin silently drops the message; nothing else to do.
            }
          }
        }

        win.addEventListener('message', onMessage);
        sayHello();
        helloTimer = win.setInterval(sayHello, HELLO_INTERVAL_MS);
        timeoutTimer = win.setTimeout(function () {
          cleanup();
          state.status = 'failed';
          state.initPromise = null;
          reject(new RanteError('timeout', 'The Rante host did not answer within ' + timeoutMs + ' ms. ' +
            'Is the app opened from My apps in the Rante Portal?'));
        }, timeoutMs);
      });
      return state.initPromise;
    }

    function request(method, params, requestOptions) {
      if (state.status !== 'connected' || !state.port) {
        return Promise.reject(new RanteError('not_connected', 'Call Rante.init() and wait for it before calling the host.'));
      }
      if (typeof method !== 'string' || !METHOD_NAME.test(method)) {
        return Promise.reject(new RanteError('invalid_request', 'Not a method name: ' + String(method)));
      }
      var timeoutMs = requestOptions && typeof requestOptions.timeoutMs === 'number' ? requestOptions.timeoutMs : DEFAULT_REQUEST_TIMEOUT_MS;
      var id = state.nextId++;
      return new Promise(function (resolve, reject) {
        var timer = win.setTimeout(function () {
          delete state.pending[id];
          reject(new RanteError('timeout', 'The Rante host did not answer "' + method + '" within ' + timeoutMs + ' ms.'));
        }, timeoutMs);
        state.pending[id] = { resolve: resolve, reject: reject, timer: timer };
        try {
          state.port.postMessage({ id: id, method: method, params: params === undefined ? {} : params });
        } catch (err) {
          delete state.pending[id];
          win.clearTimeout(timer);
          reject(new RanteError('invalid_request', 'The request could not be sent: ' + (err && err.message ? err.message : err)));
        }
      });
    }

    function requirePermission(scope) {
      if (state.status !== 'connected') {
        return new RanteError('not_connected', 'Call Rante.init() and wait for it before calling the host.');
      }
      if (state.info.permissions.indexOf(scope) < 0) {
        return new RanteError('permission_denied', 'This app does not have the "' + scope + '" permission. ' +
          'Add it to "permissions" in manifest.json; the tenant\'s admin approves it when installing the app.');
      }
      return null;
    }

    function getHostInfo() {
      if (!state.info) return null;
      return {
        protocol: state.info.protocol,
        host: { name: state.info.host.name, version: state.info.host.version },
        app: { id: state.info.app.id, version: state.info.app.version },
        permissions: state.info.permissions.slice(),
        capabilities: state.info.capabilities.slice(),
        locale: state.info.locale,
        theme: state.info.theme
      };
    }

    function getContext() {
      return request('context.get', {}).then(function (ctx) {
        ctx = isObject(ctx) ? ctx : {};
        var out = { locale: text(ctx.locale, 35) || state.info.locale, theme: ctx.theme === 'dark' ? 'dark' : 'light' };
        if (isObject(ctx.user)) {
          out.user = { id: text(ctx.user.id, 64), displayName: text(ctx.user.displayName, 256) };
          if (typeof ctx.user.email === 'string') out.user.email = text(ctx.user.email, 320);
        }
        if (isObject(ctx.tenant)) out.tenant = { id: text(ctx.tenant.id, 64), name: text(ctx.tenant.name, 256) };
        return out;
      });
    }

    function getUser() {
      var denied = requirePermission('user.read');
      if (denied) return Promise.reject(denied);
      return getContext().then(function (ctx) {
        if (!ctx.user) throw new RanteError('unavailable', 'The Rante host did not return the signed-in user.');
        return ctx.user;
      });
    }

    function getTenant() {
      var denied = requirePermission('tenant.read');
      if (denied) return Promise.reject(denied);
      return getContext().then(function (ctx) {
        if (!ctx.tenant) throw new RanteError('unavailable', 'The Rante host did not return the active tenant.');
        return ctx.tenant;
      });
    }

    function getAccessToken(tokenOptions) {
      var denied = requirePermission('auth.token');
      if (denied) return Promise.reject(denied);
      var force = !!(tokenOptions && tokenOptions.forceRefresh);
      var cached = state.tokenCache;
      if (!force && cached && cached.expiresOn - TOKEN_REFRESH_MARGIN_MS > Date.now()) {
        return Promise.resolve({ token: cached.token, expiresOn: cached.expiresOn });
      }
      return request('auth.getToken', {}, { timeoutMs: TOKEN_REQUEST_TIMEOUT_MS }).then(function (result) {
        if (!isObject(result) || typeof result.token !== 'string' || typeof result.expiresOn !== 'number') {
          throw new RanteError('host_error', 'The Rante host returned an invalid token response.');
        }
        state.tokenCache = { token: result.token, expiresOn: result.expiresOn };
        return { token: result.token, expiresOn: result.expiresOn };
      });
    }

    function notify(message, notifyOptions) {
      var denied = requirePermission('notifications');
      if (denied) return Promise.reject(denied);
      var kind = notifyOptions && notifyOptions.kind ? notifyOptions.kind : 'info';
      if (typeof message !== 'string' || message.length === 0 || message.length > 500) {
        return Promise.reject(new RanteError('invalid_request', 'A notification is a string of 1 to 500 characters.'));
      }
      if (NOTIFICATION_KINDS.indexOf(kind) < 0) {
        return Promise.reject(new RanteError('invalid_request', 'kind must be one of ' + NOTIFICATION_KINDS.join(', ') + '.'));
      }
      return request('notifications.show', { message: message, kind: kind }).then(function () {});
    }

    function openUrl(url, openOptions) {
      var denied = requirePermission('navigation');
      if (denied) return Promise.reject(denied);
      var target = openOptions && openOptions.target ? openOptions.target : 'blank';
      if (typeof url !== 'string' || !/^https:\/\//.test(url) || url.length > 2048) {
        return Promise.reject(new RanteError('invalid_request', 'url must be an https:// address of at most 2048 characters.'));
      }
      if (target !== 'blank' && target !== 'self') {
        return Promise.reject(new RanteError('invalid_request', 'target must be "blank" (a new tab) or "self" (a Rante page).'));
      }
      return request('navigation.open', { url: url, target: target }).then(function () {});
    }

    function resize(height) {
      var h = typeof height === 'number' ? height : documentHeight(win);
      if (!(h >= 0) || h > 100000) return Promise.reject(new RanteError('invalid_request', 'height must be between 0 and 100000 pixels.'));
      return request('frame.resize', { height: Math.ceil(h) }).then(function () {});
    }

    function setTitle(title) {
      if (typeof title !== 'string' || title.length > 100) {
        return Promise.reject(new RanteError('invalid_request', 'A title is a string of at most 100 characters.'));
      }
      return request('frame.setTitle', { title: title }).then(function () {});
    }

    function ready() {
      return request('frame.ready', {}).then(function () {});
    }

    function startAutoResize() {
      if (state.resize || typeof win.ResizeObserver !== 'function' || !win.document || !win.document.documentElement) return;
      var last = -1;
      var scheduled = null;
      var observer = new win.ResizeObserver(function () {
        if (scheduled !== null) return;
        scheduled = win.setTimeout(function () {
          scheduled = null;
          var h = documentHeight(win);
          if (h !== last) {
            last = h;
            resize(h).catch(function () {});
          }
        }, 100);
      });
      observer.observe(win.document.documentElement);
      state.resize = observer;
    }

    function on(event, handler) {
      if (typeof event !== 'string' || typeof handler !== 'function') throw new TypeError('on(event, handler) needs a name and a function.');
      (state.listeners[event] = state.listeners[event] || []).push(handler);
      return function () {
        off(event, handler);
      };
    }

    function off(event, handler) {
      var list = state.listeners[event];
      if (!list) return;
      var i = list.indexOf(handler);
      if (i >= 0) list.splice(i, 1);
    }

    function disconnect() {
      if (state.resize) {
        state.resize.disconnect();
        state.resize = null;
      }
      if (state.port) {
        state.port.onmessage = null;
        try {
          state.port.close();
        } catch (err) {
          // already closed
        }
      }
      Object.keys(state.pending).forEach(function (id) {
        var p = state.pending[id];
        win.clearTimeout(p.timer);
        p.reject(new RanteError('not_connected', 'Disconnected from the Rante host.'));
      });
      state.pending = {};
      state.port = null;
      state.status = 'idle';
      state.initPromise = null;
      state.tokenCache = null;
    }

    return {
      init: init,
      isConnected: function () { return state.status === 'connected'; },
      getHostInfo: getHostInfo,
      hasPermission: function (scope) { return !!state.info && state.info.permissions.indexOf(scope) >= 0; },
      supports: function (method) { return !!state.info && state.info.capabilities.indexOf(method) >= 0; },
      getContext: getContext,
      getUser: getUser,
      getTenant: getTenant,
      getAccessToken: getAccessToken,
      notify: notify,
      openUrl: openUrl,
      resize: resize,
      setTitle: setTitle,
      ready: ready,
      on: on,
      off: off,
      request: request,
      disconnect: disconnect
    };
  }

  /** The export outside a browser (for example under Node during server-side rendering). */
  function createUnavailable() {
    function unavailable() {
      return Promise.reject(new RanteError('not_in_host', 'The Rante SDK runs in a browser, inside Rante.'));
    }
    return {
      init: unavailable,
      isConnected: function () { return false; },
      getHostInfo: function () { return null; },
      hasPermission: function () { return false; },
      supports: function () { return false; },
      getContext: unavailable,
      getUser: unavailable,
      getTenant: unavailable,
      getAccessToken: unavailable,
      notify: unavailable,
      openUrl: unavailable,
      resize: unavailable,
      setTitle: unavailable,
      ready: unavailable,
      on: function () { return function () {}; },
      off: function () {},
      request: unavailable,
      disconnect: function () {}
    };
  }

  return {
    version: VERSION,
    PROTOCOL_VERSION: PROTOCOL_VERSION,
    RanteError: RanteError,
    create: create,
    createUnavailable: createUnavailable,
    internals: {
      DEFAULT_HOST_ORIGINS: DEFAULT_HOST_ORIGINS,
      HELLO_INTERVAL_MS: HELLO_INTERVAL_MS,
      normalizeHostOrigins: normalizeHostOrigins,
      readConnectInfo: readConnectInfo,
      randomId: randomId
    }
  };
});
