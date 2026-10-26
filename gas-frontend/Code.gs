/**
 * Sennin Account — GAS frontend + stateless Worker proxy.
 * Existing account routes remain unchanged. OAuth consent UI is hosted by GAS;
 * OAuth credential/code validation and token issuance remain in the Worker.
 */
var ROUTES_ = {
  register:         ['post', '/v1/register', false],
  verifyEmailCode:  ['post', '/v1/email/verify-code', false],
  login:            ['post', '/v1/login', false],
  forgotPassword:   ['post', '/v1/forgot', false],
  resetPassword:    ['post', '/v1/reset', false],
  me:               ['get',  '/v1/me', true],
  profile:          ['post', '/v1/profile', true],
  changeEmail:      ['post', '/v1/email/change', true],
  changePassword:   ['post', '/v1/password', true],
  logout:           ['post', '/v1/logout', true],
  sessions:         ['get',  '/v1/sessions', true],
  revokeSession:    ['post', '/v1/sessions/revoke', true],
  revokeOthers:     ['post', '/v1/sessions/revoke-others', true],
  pointHistory:     ['get',  '/v1/points/history', true],
  connections:      ['get',  '/v1/connections', true],
  revokeConnection: ['post', '/v1/connections/revoke', true],
  apps:             ['get',  '/v1/apps', true],
  createApp:        ['post', '/v1/apps', true],
  updateApp:        ['post', '/v1/apps/update', true],
  rotateAppSecret:  ['post', '/v1/apps/rotate', true],
  deleteApp:        ['post', '/v1/apps/delete', true]
};

function config_() {
  var p = PropertiesService.getScriptProperties();
  return {
    base: String(p.getProperty('API_BASE_URL') || '').replace(/\/+$/, ''),
    key: String(p.getProperty('APP_KEY') || '')
  };
}

function doGet(e) {
  var cfg = config_();
  var params = (e && e.parameter) || {};

  // OAuth authorization requests arrive at this GAS URL with standard OAuth parameters.
  // Existing account/reset routes continue to use Index.html.
  if (params.client_id || params.oauth === 'authorize') {
    var oauthRequest = {
      client_id: safeParam_(params.client_id, 80),
      redirect_uri: safeParam_(params.redirect_uri, 1000),
      response_type: safeParam_(params.response_type || 'code', 20),
      scope: safeParam_(params.scope || 'profile', 200),
      state: safeParam_(params.state, 300),
      code_challenge: safeParam_(params.code_challenge, 200),
      code_challenge_method: safeParam_(params.code_challenge_method, 20),
      prompt: safeParam_(params.prompt, 40)
    };

    // Resolve authoritative app metadata from the Worker-rendered consent page.
    // The Worker validates the client, active status, redirect URI and scopes
    // before it renders the page. GAS only extracts the registered display data;
    // the Worker remains responsible for all security-sensitive OAuth decisions.
    var appInfo = fetchOAuthClientInfo_(oauthRequest);
    oauthRequest.client_name = appInfo.name || '';
    oauthRequest.client_description = appInfo.description || '';
    oauthRequest.client_created_by = appInfo.createdBy || '';
    oauthRequest.client_metadata_ok = !!appInfo.ok;
    oauthRequest.client_metadata_error = appInfo.error || '';

    var tOAuth = HtmlService.createTemplateFromFile('OAuth');
    tOAuth.oauthJson = JSON.stringify(oauthRequest).replace(/</g, '\\u003c');
    return tOAuth.evaluate()
      .setTitle('Sennin Account — アクセス許可')
      .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  }

  // 管理者パネル: 〈GASのURL〉?page=admin (または ?admin)。パスワードは Worker 側で検証する
  if (params.page === 'admin' || params.admin !== undefined) {
    return HtmlService.createHtmlOutputFromFile('Admin')
      .setTitle('Sennin Account — 管理者')
      .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  }

  var raw = params.resetToken || '';
  var resetToken = /^[A-Za-z0-9_-]{20,100}$/.test(raw) ? raw : '';
  var t = HtmlService.createTemplateFromFile('Index');
  t.cfgJson = JSON.stringify({ resetToken: resetToken, apiBase: cfg.base }).replace(/</g, '\\u003c');
  return t.evaluate()
    .setTitle('Sennin Account')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}


/**
 * Reads registered app display metadata from the Worker consent page.
 * This avoids trusting a client-supplied app name and does not require a new
 * Worker endpoint. The HTML format is owned by this project's pages.js.
 * On any failure, return ok:false and do not let the UI grant consent.
 */
function fetchOAuthClientInfo_(oauthRequest) {
  var cfg = config_();
  if (!cfg.base || !oauthRequest || !oauthRequest.client_id || !oauthRequest.redirect_uri) {
    return { ok: false, name: '', description: '', createdBy: '', error: !cfg.base ? 'GASのスクリプトプロパティ API_BASE_URL が未設定です。' : 'client_id または redirect_uri が不足しています。' };
  }

  var keys = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state',
    'code_challenge', 'code_challenge_method'];
  var query = [];
  keys.forEach(function (key) {
    var value = oauthRequest[key];
    if (value !== undefined && value !== null && String(value) !== '') {
      query.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
    }
  });

  try {
    var res = UrlFetchApp.fetch(cfg.base + '/oauth/authorize?' + query.join('&'), {
      method: 'get',
      followRedirects: false,
      muteHttpExceptions: true,
      headers: { 'Accept': 'text/html' }
    });
    if (res.getResponseCode() !== 200) {
      var status = res.getResponseCode();
      var bodyText = extractWorkerResponseText_(res.getContentText() || '');
      var location = '';
      try { location = String(res.getHeaders()['Location'] || res.getHeaders()['location'] || ''); } catch (_) {}
      var detail = 'Workerの /oauth/authorize が HTTP ' + status + ' を返しました。';
      if (bodyText) detail += ' 応答: ' + bodyText.slice(0, 180);
      if (location) detail += ' リダイレクト応答です。登録済みRedirect URI・Scope・Client IDを確認してください。';
      return { ok: false, name: '', description: '', createdBy: '', error: detail };
    }

    var html = res.getContentText() || '';
    // Match the authoritative markup generated by Worker src/pages.js.
    var match = html.match(/<div class="box"><b>([\s\S]*?)<\/b>([\s\S]*?)<div style="color:#5f6368;font-size:12px;margin-top:6px">([\s\S]*?)<\/div><\/div>/i);
    if (!match) return { ok: false, name: '', description: '', createdBy: '', error: 'WorkerはHTTP 200を返しましたが、アプリ情報のHTMLを解析できませんでした。Worker側の表示HTMLが変更されている可能性があります。' };

    var name = decodeHtml_(stripTags_(match[1])).trim();
    var description = decodeHtml_(stripTags_(match[2])).trim();
    var createdBy = decodeHtml_(stripTags_(match[3])).trim();
    if (!name) return { ok: false, name: '', description: '', createdBy: '', error: 'Workerの応答からアプリ名が空で返されました。' };

    return { ok: true, name: name.slice(0, 120), description: description.slice(0, 500), createdBy: createdBy.slice(0, 80) };
  } catch (err) {
    var message = err && err.message ? String(err.message) : String(err || '不明なエラー');
    return { ok: false, name: '', description: '', createdBy: '', error: 'Workerへの接続に失敗しました: ' + message.slice(0, 180) };
  }
}

function stripTags_(value) {
  return String(value || '').replace(/<[^>]*>/g, '');
}

function decodeHtml_(value) {
  return String(value || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(Number(n)); })
    .replace(/&#x([0-9a-f]+);/gi, function (_, n) { return String.fromCharCode(parseInt(n, 16)); });
}

/**
 * GAS-hosted OAuth consent form submits here via google.script.run.
 * Worker remains the authority: it validates client, redirect_uri, scopes,
 * password, email verification, rate limits, and creates the one-time code.
 * Only the Worker is allowed to issue the authorization code.
 */
function oauthAuthorize(payload) {
  try {
    payload = payload && typeof payload === 'object' ? payload : {};
    var cfg = config_();
    if (!cfg.base || /REPLACE_WITH/.test(cfg.base)) {
      return { ok: false, error: 'スクリプト プロパティ API_BASE_URL に実際のWorker URLを設定してください。' };
    }

    var p = {
      response_type: String(payload.response_type || ''),
      client_id: String(payload.client_id || ''),
      redirect_uri: String(payload.redirect_uri || ''),
      scope: String(payload.scope || ''),
      state: String(payload.state || ''),
      code_challenge: String(payload.code_challenge || ''),
      code_challenge_method: String(payload.code_challenge_method || ''),
      decision: String(payload.decision || ''),
      email: String(payload.email || ''),
      password: String(payload.password || ''),
      session_token: String(payload.session_token || '')
    };
    if (p.client_id.length > 80 || p.redirect_uri.length > 1000 ||
        p.state.length > 300 || p.scope.length > 200 ||
        p.email.length > 320 || p.password.length > 200) {
      return { ok: false, error: '入力が長すぎます。認可リクエストを確認してください。' };
    }
    if (p.decision !== 'allow' && p.decision !== 'allow_session' && p.decision !== 'deny') {
      return { ok: false, error: '不正な操作です。' };
    }
    if (!p.client_id || !p.redirect_uri || p.response_type !== 'code') {
      return { ok: false, error: 'OAuthリクエストが不足しています。client_id / redirect_uri / response_type=code を確認してください。' };
    }
    if (p.decision === 'allow_session' && !/^ses_[A-Za-z0-9_-]{20,80}$/.test(p.session_token)) {
      return { ok: false, error: 'ログイン状態を確認できません。別のアカウントでログインしてください。' };
    }
    if (p.decision === 'allow' && (!p.email || !p.password)) {
      return { ok: false, error: 'メールアドレスとパスワードを入力してください。' };
    }

    var form = [];
    Object.keys(p).forEach(function(k) {
      if (p[k] !== '') form.push(encodeURIComponent(k) + '=' + encodeURIComponent(p[k]));
    });
    var res = UrlFetchApp.fetch(cfg.base + '/oauth/authorize', {
      method: 'post',
      contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
      payload: form.join('&'),
      followRedirects: false,
      muteHttpExceptions: true,
      headers: { 'Accept': 'text/html' }
    });
    var status = res.getResponseCode();
    var headers = res.getAllHeaders() || {};
    var location = headers.Location || headers.location || '';
    if (status >= 300 && status < 400 && location) {
      // Defense in depth: only allow redirect to the exact registered URI path.
      // The Worker validates redirect_uri against the client's registered URI list.
      // Apps Script's runtime does not consistently expose the WHATWG URL API.
      // Parse absolute redirect URLs with a small, deterministic helper instead.
      var target = parseAbsoluteUrl_(location);
      var registered = parseAbsoluteUrl_(p.redirect_uri);
      if (!target || !registered || target.origin !== registered.origin || target.pathname !== registered.pathname) {
        return { ok: false, error: '認可サーバーが登録済みRedirect URI以外へのリダイレクトを返しました。処理を中止しました。' };
      }
      return { ok: true, redirect: location, denied: p.decision === 'deny' };
    }

    var body = res.getContentText() || '';
    var message = extractWorkerMessage_(body);
    if (!message) {
      if (status === 429) message = 'アクセスが多すぎます。少し待ってから再試行してください。';
      else if (status >= 500) message = '認可サーバーでエラーが発生しました。Workerの設定とログを確認してください。';
      else message = '認可リクエストに失敗しました（HTTP ' + status + '）。Client ID、Redirect URI、Scopeを確認してください。';
    }
    return { ok: false, status: status, error: message };
  } catch (err) {
    // Never return stack traces, submitted credentials, or configuration secrets.
    // The message helps distinguish fetch failures from GAS-side runtime errors.
    var detail = err && err.message ? String(err.message).slice(0, 180) : '詳細不明';
    return { ok: false, error: '認可処理中にGAS側でエラーが発生しました: ' + detail };
  }
}

function parseAbsoluteUrl_(value) {
  value = String(value || '').trim();
  // Scheme, authority, path, query and fragment; query/fragment are not part of pathname.
  var m = value.match(/^([a-z][a-z0-9+.-]*):\/\/([^\/?#]+)([^?#]*)(?:\?[^#]*)?(?:#.*)?$/i);
  if (!m || m[2].indexOf('@') !== -1) return null;
  var scheme = m[1].toLowerCase();
  var authority = m[2].toLowerCase();
  if ((scheme === 'https' && /:443$/.test(authority)) || (scheme === 'http' && /:80$/.test(authority))) {
    authority = authority.replace(/:(443|80)$/, '');
  }
  return { origin: scheme + '://' + authority, pathname: m[3] || '/' };
}

function safeParam_(v, max) {
  v = String(v == null ? '' : v);
  return v.length <= max ? v : v.slice(0, max);
}

function extractWorkerResponseText_(html) {
  // Worker error pages embed a large CSS block before the actual message.
  // Remove style/script/comments first, otherwise diagnostics are truncated by :root{...}.
  var source = String(html || '')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  var title = '';
  var message = '';
  var titleMatch = source.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  var messageMatch = source.match(/<p\b[^>]*class=["'][^"']*\bsub\b[^"']*["'][^>]*>([\s\S]*?)<\/p>/i);
  if (titleMatch) title = decodeHtml_(stripTags_(titleMatch[1])).replace(/\s+/g, ' ').trim();
  if (messageMatch) message = decodeHtml_(stripTags_(messageMatch[1])).replace(/\s+/g, ' ').trim();
  var result = [title, message].filter(Boolean).join(' — ');
  if (!result) result = decodeHtml_(stripTags_(source)).replace(/\s+/g, ' ').trim();
  return result.slice(0, 500);
}

function extractWorkerMessage_(html) {
  return extractWorkerResponseText_(html);
}

/**
 * Existing account API proxy. Unchanged behavior.
 */
function api(action, payload, token) {
  var route = ROUTES_[action];
  if (!route) return { ok: false, status: 400, error: '未対応の操作です' };
  var cfg = config_();
  if (!cfg.base || !cfg.key) {
    return { ok: false, status: 500, error: 'スクリプトプロパティ API_BASE_URL / APP_KEY を設定してください' };
  }
  var headers = { 'X-App-Key': cfg.key };
  if (route[2]) {
    if (!token || !/^ses_[A-Za-z0-9_-]{20,80}$/.test(String(token))) {
      return { ok: false, status: 401, error: 'ログインが必要です' };
    }
    headers.Authorization = 'Bearer ' + token;
  }
  var options = { method: route[0], muteHttpExceptions: true, headers: headers, followRedirects: false };
  if (route[0] === 'post') {
    var body = JSON.stringify(payload && typeof payload === 'object' ? payload : {});
    if (body.length > 30000) return { ok: false, status: 413, error: '入力が大きすぎます' };
    options.contentType = 'application/json';
    options.payload = body;
  }
  var res;
  try {
    res = UrlFetchApp.fetch(cfg.base + route[1], options);
  } catch (err) {
    return { ok: false, status: 502, error: 'APIに接続できませんでした' };
  }
  var out;
  try { out = JSON.parse(res.getContentText()); } catch (err) { out = null; }
  if (!out || typeof out !== 'object') return { ok: false, status: res.getResponseCode(), error: 'APIから不正な応答が返りました' };
  out.status = res.getResponseCode();
  if (out.status >= 400) out.ok = false;
  return out;
}

/**
 * 管理者パネル用の中継。Worker の /v1/admin/* を呼ぶ(APP_KEY で保護)。
 * 管理者トークン・CSRFトークンはブラウザ側のメモリにのみ保持し、GAS 側には保存しない。
 * method: 'GET' | 'POST' / path: '/stats' 等(クエリ付き可) / body: オブジェクト
 */
var ADMIN_PATH_RE_ = /^\/(login|logout|session|stats|users|points\/distribute|apps|audit|users\/[\w-]{1,64}(\/[a-z][a-z-]{0,40})?|apps\/[\w-]{1,64}\/(update|rotate|delete))$/;

function adminCall(method, path, body, token, csrf) {
  try {
    method = method === 'POST' ? 'POST' : 'GET';
    path = String(path || '');
    var qi = path.indexOf('?');
    var pathname = qi < 0 ? path : path.slice(0, qi);
    var query = qi < 0 ? '' : path.slice(qi);
    if (!ADMIN_PATH_RE_.test(pathname) || !/^(\?[\w%=&.+~!*'()-]*)?$/.test(query)) {
      return { ok: false, status: 404, error: '不正な操作です' };
    }
    var cfg = config_();
    if (!cfg.base || !cfg.key) {
      return { ok: false, status: 500, error: 'スクリプトプロパティ API_BASE_URL / APP_KEY を設定してください' };
    }
    var headers = { 'X-App-Key': cfg.key };
    if (pathname !== '/login') {
      if (!/^adm_[A-Za-z0-9_-]{20,80}$/.test(String(token || ''))) {
        return { ok: false, status: 401, error: 'ログインが必要です' };
      }
      headers['X-Admin-Token'] = String(token);
    }
    var options = { method: method.toLowerCase(), muteHttpExceptions: true, headers: headers, followRedirects: false };
    if (method === 'POST') {
      var text = JSON.stringify(body && typeof body === 'object' ? body : {});
      if (text.length > 30000) return { ok: false, status: 413, error: '入力が大きすぎます' };
      options.contentType = 'application/json';
      options.payload = text;
      if (csrf) headers['X-CSRF-Token'] = String(csrf).slice(0, 100);
    }
    var res;
    try {
      res = UrlFetchApp.fetch(config_().base + '/v1/admin' + pathname + query, options);
    } catch (err) {
      return { ok: false, status: 502, error: 'APIに接続できませんでした' };
    }
    var out;
    try { out = JSON.parse(res.getContentText()); } catch (err) { out = null; }
    if (!out || typeof out !== 'object') return { ok: false, status: res.getResponseCode(), error: 'APIから不正な応答が返りました' };
    out.status = res.getResponseCode();
    if (out.status >= 400) out.ok = false;
    return out;
  } catch (err) {
    return { ok: false, status: 500, error: '管理者API中継でエラーが発生しました' };
  }
}

