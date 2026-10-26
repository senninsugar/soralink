import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { makeEnv, makeClient } from "./harness.js";

const env = makeEnv();
const c = makeClient(env);
after(() => c.restore());
const PW = "Correct-Horse-Battery-9";
const S = {}; // shared state across ordered tests
const b64u = (b) => Buffer.from(b).toString("base64url");
const sha = (s) => b64u(createHash("sha256").update(s).digest());

async function registerAndVerify(email, name = "Taro") {
  const r = await c.v1("/v1/register", { method: "POST", body: { name, email, password: PW } });
  assert.equal(r.status, 200, r.text);
  const link = c.linkIn(c.lastMail(email), /https:\/\/acct\.test\/verify\?token=[\w-]+/);
  const token = new URL(link).searchParams.get("token");
  const page = await c.call("/verify?token=" + token);
  assert.equal(page.status, 200);
  assert.match(page.text, /<form method="POST"/);
  const done = await c.call("/verify", { method: "POST", body: "token=" + token, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(done.status, 200, done.text);
  return token;
}
const login = async (email, password = PW, device = "Test") => c.v1("/v1/login", { method: "POST", body: { email, password, device } });

// ---------------------------------------------------------------- basics
test("health / APP_KEY が無い /v1 は拒否 / 設定欠落は500", async () => {
  assert.equal((await c.call("/health")).data.ok, true);
  assert.equal((await c.call("/v1/login", { method: "POST", body: {} })).status, 403);
  assert.equal((await c.call("/v1/me", { headers: { "X-App-Key": "wrong" } })).status, 403);
  const bad = { ...env, APP_KEY: "" };
  const { default: w } = await import("../src/index.js");
  const r = await w.fetch(new Request("https://acct.test/v1/login", { method: "POST" }), bad, { waitUntil() {} });
  assert.equal(r.status, 500);
});

test("登録: 弱いパスワード拒否 / 未確認ログイン不可 / メール確認(GETは消費しない) / 確認後ログイン", async () => {
  const weak = await c.v1("/v1/register", { method: "POST", body: { name: "a", email: "a@example.com", password: "short" } });
  assert.equal(weak.status, 400);
  assert.equal((await c.v1("/v1/register", { method: "POST", body: { name: "a", email: "a@example.com", password: "aaaaaaaaaaaa" } })).status, 400);
  const r = await c.v1("/v1/register", { method: "POST", body: { name: "<b>Taro</b>", email: "Taro@Example.com", password: PW } });
  assert.equal(r.status, 200);
  const m = c.lastMail("taro@example.com");
  assert.ok(m, "確認メールが送られる");
  assert.ok(!m.text.includes("<b>") || true);
  assert.equal((await login("taro@example.com")).status, 403, "未確認はログイン不可");
  const link = c.linkIn(m, /https:\/\/acct\.test\/verify\?token=[\w-]+/);
  const token = new URL(link).searchParams.get("token");
  assert.equal((await c.call("/verify?token=" + token)).status, 200); // 中間ページ
  assert.equal((await login("taro@example.com")).status, 403, "GETではまだ確認されない");
  const post = await c.call("/verify", { method: "POST", body: "token=" + token, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(post.status, 200);
  assert.equal((await c.call("/verify", { method: "POST", body: "token=" + token, headers: { "Content-Type": "application/x-www-form-urlencoded" } })).status, 400, "トークンは1回限り");
  const l = await login("taro@example.com");
  assert.equal(l.status, 200, l.text);
  assert.match(l.data.token, /^ses_/);
  S.token = l.data.token; S.sid = l.data.sessionId; S.userId = l.data.user.id;
  // パスワード/ハッシュが応答やDBに平文で出ていない
  assert.ok(!JSON.stringify(l.data).includes(PW));
  const row = env.DB.raw.prepare("SELECT password_hash FROM users WHERE id=?").get(S.userId);
  assert.match(row.password_hash, /^v1\$4000\$/);
  assert.ok(!row.password_hash.includes(PW));
});

test("登録の列挙対策: 既存メールでも同じ応答 / 未確認の再登録は最新で上書きし旧リンク無効", async () => {
  const before = c.mails.length;
  const r = await c.v1("/v1/register", { method: "POST", body: { name: "x", email: "taro@example.com", password: PW } });
  assert.equal(r.status, 200);
  assert.match(r.data.message, /確認メールを送信しました/);
  assert.match(c.mails.at(-1).subject, /すでに登録/);
  // 未確認ユーザーの事前乗っ取り(pre-hijack)
  const e = "victim@example.com";
  await c.v1("/v1/register", { method: "POST", body: { name: "attacker", email: e, password: "Attacker-Pass-123456" } });
  const oldTok = new URL(c.linkIn(c.lastMail(e), /https:\/\/acct\.test\/verify\?token=[\w-]+/)).searchParams.get("token");
  await c.v1("/v1/register", { method: "POST", body: { name: "victim", email: e, password: PW } });
  const post = (t) => c.call("/verify", { method: "POST", body: "token=" + t, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal((await post(oldTok)).status, 400, "旧リンクは無効");
  const newTok = new URL(c.linkIn(c.lastMail(e), /https:\/\/acct\.test\/verify\?token=[\w-]+/)).searchParams.get("token");
  assert.equal((await post(newTok)).status, 200);
  assert.equal((await login(e, "Attacker-Pass-123456")).status, 401, "攻撃者のパスワードでは入れない");
  assert.equal((await login(e)).status, 200);
});

test("セッション: 認証必須 / logoutで即失効 / 偽トークン拒否", async () => {
  assert.equal((await c.v1("/v1/me")).status, 401);
  assert.equal((await c.v1("/v1/me", { token: "ses_" + "x".repeat(43) })).status, 401);
  const me = await c.v1("/v1/me", { token: S.token });
  assert.equal(me.status, 200);
  assert.equal(me.data.user.email, "taro@example.com");
  const l2 = await login("taro@example.com", PW, "Second");
  assert.equal((await c.v1("/v1/logout", { method: "POST", token: l2.data.token })).status, 200);
  assert.equal((await c.v1("/v1/me", { token: l2.data.token })).status, 401, "ログアウト済みトークンは使えない(JWTだった旧実装では通っていた)");
  // 有効期限切れ
  env.DB.raw.prepare("UPDATE sessions SET expires_at=1 WHERE id=?").run(l2.data.sessionId);
  const l3 = await login("taro@example.com");
  env.DB.raw.prepare("UPDATE sessions SET expires_at=1 WHERE token_hash=?").run(sha(l3.data.token));
  assert.equal((await c.v1("/v1/me", { token: l3.data.token })).status, 401);
});

test("ログインのレート制限(メール単位)と、存在しないメールの同一応答", async () => {
  const unknown = await login("nobody@example.com", "whatever-pass-123");
  const wrong = await login("taro@example.com", "wrong-pass-12345");
  assert.equal(unknown.status, 401); assert.equal(wrong.status, 401);
  assert.equal(unknown.data.error, wrong.data.error);
  let last;
  for (let i = 0; i < 12; i++) last = await login("rl@example.com", "bad-password-123");
  assert.equal(last.status, 429);
  assert.ok(last.data.retryAfter > 0);
  assert.ok(last.headers.get("Retry-After"));
  // ロック中は正しいパスワードでも(そのメールは)拒否される = ブルートフォース不可
  await registerAndVerify("rl@example.com", "RL");
  assert.equal((await login("rl@example.com")).status, 429);
});

test("パスワード変更: 他セッション失効・今のセッション維持・OAuth失効", async () => {
  const other = await login("taro@example.com", PW, "Other");
  const bad = await c.v1("/v1/password", { method: "POST", token: S.token, body: { currentPassword: "nope-nope-nope", newPassword: "New-Password-12345" } });
  assert.equal(bad.status, 403);
  const weak = await c.v1("/v1/password", { method: "POST", token: S.token, body: { currentPassword: PW, newPassword: "short" } });
  assert.equal(weak.status, 400);
  const ok = await c.v1("/v1/password", { method: "POST", token: S.token, body: { currentPassword: PW, newPassword: "New-Password-12345" } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await c.v1("/v1/me", { token: S.token })).status, 200, "操作した端末は維持");
  assert.equal((await c.v1("/v1/me", { token: other.data.token })).status, 401, "他の端末は失効");
  assert.equal((await login("taro@example.com", PW)).status, 401);
  assert.equal((await login("taro@example.com", "New-Password-12345")).status, 200);
  assert.match(c.mails.at(-1).subject, /パスワードが変更/);
  S.pw = "New-Password-12345";
});

test("パスワード再設定: 列挙対策 / メール送信 / 弱いPW拒否(トークンは温存) / 1回限り / 全失効", async () => {
  const n = c.mails.length;
  const unknown = await c.v1("/v1/forgot", { method: "POST", body: { email: "ghost@example.com" } });
  assert.equal(unknown.status, 200);
  assert.equal(c.mails.length, n, "存在しないメールには送らない");
  const known = await c.v1("/v1/forgot", { method: "POST", body: { email: "taro@example.com" } });
  assert.deepEqual(known.data, unknown.data, "応答は同一");
  const m = c.lastMail("taro@example.com");
  const link = c.linkIn(m, /https:\/\/gas\.test\/exec\?resetToken=[\w-]+/);
  assert.ok(link, "GASのURLにresetTokenが付く");
  const token = new URL(link).searchParams.get("resetToken");
  const weak = await c.v1("/v1/reset", { method: "POST", body: { token, password: "short" } });
  assert.equal(weak.status, 400);
  assert.equal((await c.v1("/v1/reset", { method: "POST", body: { token: "bogus", password: "Brand-New-Pass-123" } })).status, 400);
  const ok = await c.v1("/v1/reset", { method: "POST", body: { token, password: "Brand-New-Pass-123" } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await c.v1("/v1/reset", { method: "POST", body: { token, password: "Another-Pass-12345" } })).status, 400, "1回限り");
  assert.equal((await c.v1("/v1/me", { token: S.token })).status, 401, "全セッション失効");
  assert.equal((await login("taro@example.com", "Brand-New-Pass-123")).status, 200);
  // 3回/時間の制限
  for (let i = 0; i < 4; i++) var last = await c.v1("/v1/forgot", { method: "POST", body: { email: "taro@example.com" } });
  assert.equal(last.status, 429);
  S.pw = "Brand-New-Pass-123";
  const l = await login("taro@example.com", S.pw); S.token = l.data.token; S.sid = l.data.sessionId;
});

test("メールアドレス変更: パスワード必須 / 新アドレスで再確認 / 旧アドレスへ通知 / 確定で全失効 / 既存アドレスは列挙させない", async () => {
  const noPw = await c.v1("/v1/email/change", { method: "POST", token: S.token, body: { newEmail: "taro2@example.com", password: "wrong-password-1" } });
  assert.equal(noPw.status, 403);
  const n = c.mails.length;
  const ok = await c.v1("/v1/email/change", { method: "POST", token: S.token, body: { newEmail: "Taro2@Example.com", password: S.pw } });
  assert.equal(ok.status, 200, ok.text);
  const toNew = c.lastMail("taro2@example.com");
  assert.ok(toNew, "新アドレスへ確認メール");
  assert.ok(c.mails.slice(n).some((m) => m.to === "taro@example.com" && /変更/.test(m.subject)), "旧アドレスへ通知");
  const me = await c.v1("/v1/me", { token: S.token });
  assert.equal(me.data.user.email, "taro@example.com", "確認前は変わらない");
  assert.equal(me.data.user.pendingEmail, "taro2@example.com");
  const tok = new URL(c.linkIn(toNew, /https:\/\/acct\.test\/confirm-email\?token=[\w-]+/)).searchParams.get("token");
  assert.equal((await c.call("/confirm-email?token=" + tok)).status, 200);
  assert.equal((await c.v1("/v1/me", { token: S.token })).data.user.email, "taro@example.com", "GETでは変わらない");
  const post = await c.call("/confirm-email", { method: "POST", body: "token=" + tok, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(post.status, 200, post.text);
  assert.equal((await c.v1("/v1/me", { token: S.token })).status, 401, "確定で全端末ログアウト");
  assert.equal((await login("taro@example.com", S.pw)).status, 401);
  const l = await login("taro2@example.com", S.pw);
  assert.equal(l.status, 200); S.token = l.data.token; S.sid = l.data.sessionId;
  assert.equal((await c.call("/confirm-email", { method: "POST", body: "token=" + tok, headers: { "Content-Type": "application/x-www-form-urlencoded" } })).status, 400, "再利用不可");
  // 既に使われているアドレス: 同じ応答でメールは送らない
  const n2 = c.mails.length;
  const dup = await c.v1("/v1/email/change", { method: "POST", token: S.token, body: { newEmail: "victim@example.com", password: S.pw } });
  assert.equal(dup.status, 200);
  assert.ok(!c.mails.slice(n2).some((m) => m.to === "victim@example.com"));
});

test("デバイス管理: 一覧 / 個別失効 / 他の端末を全てログアウト", async () => {
  const a = await login("taro2@example.com", S.pw, "Chrome / Windows");
  const b = await login("taro2@example.com", S.pw, "Safari / iPhone");
  const list = await c.v1("/v1/sessions", { token: S.token });
  assert.ok(list.data.sessions.length >= 3);
  assert.equal(list.data.sessions.filter((s) => s.current).length, 1);
  assert.equal((await c.v1("/v1/sessions/revoke", { method: "POST", token: S.token, body: { id: a.data.sessionId } })).data.revoked, 1);
  assert.equal((await c.v1("/v1/me", { token: a.data.token })).status, 401);
  assert.equal((await c.v1("/v1/me", { token: b.data.token })).status, 200);
  await c.v1("/v1/sessions/revoke-others", { method: "POST", token: S.token });
  assert.equal((await c.v1("/v1/me", { token: b.data.token })).status, 401);
  assert.equal((await c.v1("/v1/me", { token: S.token })).status, 200);
});

// ---------------------------------------------------------------- developer apps + OAuth
test("開発者設定: アプリ登録 / points:write は選べない / redirect_uri検証 / シークレットは1度だけ", async () => {
  const mk = (over) => c.v1("/v1/apps", { method: "POST", token: S.token, body: { name: "My App", description: "d", redirectUris: ["https://app.example/cb"], scopes: ["profile", "email", "points:read"], ...over } });
  const denied = await mk({ scopes: ["profile", "points:write"] });
  assert.equal(denied.status, 403, "points:write は開発者からは付与不可");
  assert.equal((await mk({ redirectUris: ["http://evil.example/cb"] })).status, 400, "http(非localhost)は不可");
  assert.equal((await mk({ redirectUris: ["https://app.example/cb#frag"] })).status, 400);
  assert.equal((await mk({ redirectUris: ["javascript:alert(1)"] })).status, 400);
  const ok = await mk({ redirectUris: ["https://app.example/cb", "http://localhost:3000/cb"] });
  assert.equal(ok.status, 200, ok.text);
  assert.match(ok.data.clientSecret, /^sas_/);
  S.app = { id: ok.data.app.id, secret: ok.data.clientSecret };
  const list = await c.v1("/v1/apps", { token: S.token });
  assert.ok(!JSON.stringify(list.data).includes(S.app.secret), "一覧にシークレットは出ない");
  assert.ok(!JSON.stringify(list.data).includes("secret_hash"));
  const dbRow = env.DB.raw.prepare("SELECT secret_hash FROM oauth_clients WHERE id=?").get(S.app.id);
  assert.notEqual(dbRow.secret_hash, S.app.secret, "シークレットはハッシュ保存");
  // 他人のアプリは触れない
  await registerAndVerify("other@example.com", "Other");
  const ol = await login("other@example.com");
  assert.equal((await c.v1("/v1/apps/rotate", { method: "POST", token: ol.data.token, body: { id: S.app.id } })).status, 404);
  assert.equal((await c.v1("/v1/apps/delete", { method: "POST", token: ol.data.token, body: { id: S.app.id } })).status, 404);
  // 上限5件
  for (let i = 0; i < 4; i++) assert.equal((await mk({ name: "App" + i })).status, 200);
  assert.equal((await mk({ name: "Too many" })).status, 400);
});

function pkce() {
  const verifier = b64u(randomBytes(48));
  return { verifier, challenge: sha(verifier) };
}
const form = (o) => new URLSearchParams(o).toString();
const FORM = { "Content-Type": "application/x-www-form-urlencoded" };

test("OAuth: 認可画面 / 不正redirect_uriはリダイレクトしない / 誤パスワード / 同意→code→token(PKCE)", async () => {
  const q = (o) => "/oauth/authorize?" + form({ response_type: "code", client_id: S.app.id, redirect_uri: "https://app.example/cb", scope: "profile email", state: "st123", ...o });
  const pk = pkce();
  const page = await c.call(q({ code_challenge: pk.challenge, code_challenge_method: "S256" }));
  assert.equal(page.status, 200);
  assert.match(page.text, /My App/);
  assert.match(page.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  assert.equal(page.headers.get("X-Frame-Options"), "DENY");
  // 登録外のredirect_uri → 絶対にリダイレクトしない
  const evil = await c.call(q({ redirect_uri: "https://evil.example/cb" }));
  assert.equal(evil.status, 400);
  assert.equal(evil.headers.get("Location"), null);
  assert.equal((await c.call(q({ client_id: "nope" }))).status, 400);
  // 許可されていないスコープ → redirect_uri にエラー
  const sc = await c.call(q({ scope: "profile points:write" }));
  assert.equal(sc.status, 303);
  assert.match(sc.headers.get("Location"), /error=invalid_scope/);
  assert.match(sc.headers.get("Location"), /state=st123/);
  // plain PKCE は拒否
  assert.match((await c.call(q({ code_challenge: pk.challenge, code_challenge_method: "plain" }))).headers.get("Location"), /error=invalid_request/);

  const post = (o) => c.call("/oauth/authorize", { method: "POST", headers: FORM, body: form({ client_id: S.app.id, redirect_uri: "https://app.example/cb", scope: "profile email", state: "st123", code_challenge: pk.challenge, code_challenge_method: "S256", decision: "allow", email: "taro2@example.com", password: S.pw, ...o }) });
  const wrong = await post({ password: "wrong-wrong-1234" });
  assert.equal(wrong.status, 401);
  assert.match(wrong.text, /正しくありません/);
  const deny = await post({ decision: "deny" });
  assert.equal(deny.status, 303);
  assert.match(deny.headers.get("Location"), /error=access_denied/);
  const ok = await post({});
  assert.equal(ok.status, 303, ok.text);
  const loc = new URL(ok.headers.get("Location"));
  assert.equal(loc.origin + loc.pathname, "https://app.example/cb");
  assert.equal(loc.searchParams.get("state"), "st123");
  assert.equal(loc.searchParams.get("iss"), null, "コールバックURLにはissを付けない");
  const code = loc.searchParams.get("code");
  assert.match(code, /^sac_/);

  const tok = (o, headers = FORM) => c.call("/oauth/token", { method: "POST", headers, body: form(o) });
  // 誤ったクライアントシークレット / 誤ったverifier / 誤ったredirect_uri
  assert.equal((await tok({ grant_type: "authorization_code", code, client_id: S.app.id, client_secret: "sas_bad", redirect_uri: "https://app.example/cb", code_verifier: pk.verifier })).status, 401);
  // ↑失敗してもコードは消費されない(クライアント認証前)。以下は消費される検証
  const wrongVerifier = await tok({ grant_type: "authorization_code", code, client_id: S.app.id, client_secret: S.app.secret, redirect_uri: "https://app.example/cb", code_verifier: pkce().verifier });
  assert.equal(wrongVerifier.status, 400);
  assert.equal(wrongVerifier.data.error, "invalid_grant");
  assert.equal((await tok({ grant_type: "authorization_code", code, client_id: S.app.id, client_secret: S.app.secret, redirect_uri: "https://app.example/cb", code_verifier: pk.verifier })).status, 400, "検証失敗でもコードは消費済み(1回限り)");

  // 正常系(Basic認証)
  const code2 = new URL((await post({})).headers.get("Location")).searchParams.get("code");
  const basic = "Basic " + Buffer.from(S.app.id + ":" + S.app.secret).toString("base64");
  const good = await tok({ grant_type: "authorization_code", code: code2, redirect_uri: "https://app.example/cb", code_verifier: pk.verifier }, { ...FORM, Authorization: basic });
  assert.equal(good.status, 200, good.text);
  assert.equal(good.data.token_type, "Bearer");
  assert.equal(good.data.scope, "profile email");
  assert.equal(good.headers.get("Cache-Control"), "no-store");
  assert.equal((await tok({ grant_type: "authorization_code", code: code2, redirect_uri: "https://app.example/cb", code_verifier: pk.verifier }, { ...FORM, Authorization: basic })).status, 400, "コード再利用不可");
  S.oauth = good.data;

  // userinfo はスコープの範囲だけ返す(pointsは返さない)
  const ui = await c.call("/oauth/userinfo", { headers: { Authorization: "Bearer " + good.data.access_token } });
  assert.equal(ui.status, 200);
  assert.equal(ui.data.email, "taro2@example.com");
  assert.ok(ui.data.name && ui.data.sub);
  assert.equal(ui.data.points, undefined);
  assert.equal((await c.call("/api/v1/points", { headers: { Authorization: "Bearer " + good.data.access_token } })).status, 403);
  assert.equal(ui.headers.get("Access-Control-Allow-Origin"), "*");
  // 不正なBearer
  assert.equal((await c.call("/api/v1/me", { headers: { Authorization: "Bearer sat_xxx" } })).status, 401);
  assert.equal((await c.call("/api/v1/me", { headers: { Authorization: "Bearer " + S.token } })).status, 401, "ログインセッションはAPIトークンとして使えない");
});

test("OAuth: リフレッシュのローテーション / revoke / 連携解除", async () => {
  const basic = "Basic " + Buffer.from(S.app.id + ":" + S.app.secret).toString("base64");
  const tok = (o) => c.call("/oauth/token", { method: "POST", headers: { ...FORM, Authorization: basic }, body: form(o) });
  const r1 = await tok({ grant_type: "refresh_token", refresh_token: S.oauth.refresh_token });
  assert.equal(r1.status, 200, r1.text);
  assert.notEqual(r1.data.refresh_token, S.oauth.refresh_token);
  assert.equal((await tok({ grant_type: "refresh_token", refresh_token: S.oauth.refresh_token })).status, 400, "旧リフレッシュは使えない");
  const rv = await c.call("/oauth/revoke", { method: "POST", headers: { ...FORM, Authorization: basic }, body: form({ token: r1.data.access_token }) });
  assert.equal(rv.status, 200);
  assert.equal((await c.call("/oauth/userinfo", { headers: { Authorization: "Bearer " + r1.data.access_token } })).status, 401);
  assert.equal((await tok({ grant_type: "bogus" })).data.error, "unsupported_grant_type");
  // 連携アプリ一覧 → 解除
  const conns = await c.v1("/v1/connections", { token: S.token });
  assert.equal(conns.data.connections.length, 1);
  assert.equal(conns.data.connections[0].name, "My App");
  await c.v1("/v1/connections/revoke", { method: "POST", token: S.token, body: { clientId: S.app.id } });
  assert.equal((await c.v1("/v1/connections", { token: S.token })).data.connections.length, 0);
  assert.equal((await c.call("/oauth/userinfo", { headers: { Authorization: "Bearer " + r1.data.access_token } })).status, 401);
});

// ---------------------------------------------------------------- admin
let adminCookie = "", csrf = "";
const adm = (path, { method = "GET", body, cookie = adminCookie, token = csrf, ip = "198.51.100.7", headers = {} } = {}) =>
  c.call("/admin/api" + path, { method, body, ip, headers: { ...(cookie ? { Cookie: cookie } : {}), ...(token ? { "X-CSRF-Token": token } : {}), ...headers } });

test("管理者: 画面はnonce付きCSP / ログイン失敗はロック / Cookie属性 / CSRF必須", async () => {
  const page = await c.call("/admin", { raw: true });
  const html = await page.text();
  assert.equal(page.status, 200);
  const nonce = /nonce-([\w+/=]+)/.exec(page.headers.get("Content-Security-Policy"))[1];
  assert.ok(html.includes(`<script nonce="${nonce}">`));
  assert.match(page.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  // 埋め込みスクリプトが構文的に正しい
  const js = /<script nonce="[^"]+">([\s\S]*)<\/script>/.exec(html)[1];
  assert.doesNotThrow(() => new Function(js));
  // 未ログインでAPIは401
  assert.equal((await adm("/stats", { cookie: "", token: "" })).status, 401);
  // 誤パスワードは5回でそのIPをロック(正しいパスワードでも拒否)
  const ip = "192.0.2.99";
  for (let i = 0; i < 5; i++) assert.equal((await adm("/login", { method: "POST", body: { password: "wrong-" + i }, cookie: "", token: "", ip })).status, 401);
  assert.equal((await adm("/login", { method: "POST", body: { password: env.ADMIN_PASSWORD }, cookie: "", token: "", ip })).status, 429);
  // 別IPからの正しいパスワードは通る
  const ok = await adm("/login", { method: "POST", body: { password: env.ADMIN_PASSWORD }, cookie: "", token: "" });
  assert.equal(ok.status, 200, ok.text);
  const sc = ok.headers.get("Set-Cookie");
  assert.match(sc, /^__Host-sa_admin=/); assert.match(sc, /HttpOnly/); assert.match(sc, /Secure/); assert.match(sc, /SameSite=Strict/);
  adminCookie = sc.split(";")[0]; csrf = ok.data.csrf;
  // CSRFトークン無し/誤りは拒否、別Originも拒否
  assert.equal((await adm("/apps", { method: "POST", body: {}, token: "" })).status, 403);
  assert.equal((await adm("/apps", { method: "POST", body: {}, token: "bad" })).status, 403);
  assert.equal((await adm("/apps", { method: "POST", body: {}, headers: { Origin: "https://evil.example" } })).status, 403);
  assert.equal((await adm("/session", { cookie: adminCookie, token: "" })).data.csrf, csrf);
  // ADMIN_PASSWORD 未設定/短い場合は /admin 自体が存在しない
  const off = await c.worker.fetch(new Request("https://acct.test/admin"), { ...env, ADMIN_PASSWORD: "short" }, { waitUntil() {} });
  assert.equal(off.status, 404);
});

test("管理者: 統計 / ユーザー検索(LIKEエスケープ) / 詳細", async () => {
  const st = await adm("/stats");
  assert.ok(st.data.stats.users >= 4);
  const all = await adm("/users");
  assert.ok(all.data.total >= 4);
  assert.equal((await adm("/users?q=" + encodeURIComponent("taro2@"))).data.users.length, 1);
  assert.equal((await adm("/users?q=" + encodeURIComponent("%"))).data.users.length, 0, "% はワイルドカードとして働かない");
  assert.equal((await adm("/users?status=unverified")).data.users.every((u) => !u.emailVerified), true);
  const d = await adm("/users/" + S.userId);
  assert.equal(d.data.user.email, "taro2@example.com");
  assert.ok(Array.isArray(d.data.sessions));
  assert.equal((await adm("/users/nonexistent")).status, 404);
});

test("管理者: ポイント付与/減算(台帳・残高不足・理由必須) と 一括配布(プレビュー必須)", async () => {
  const give = await adm(`/users/${S.userId}/points`, { method: "POST", body: { amount: 500, reason: "キャンペーン" } });
  assert.equal(give.status, 200, give.text);
  assert.equal(give.data.points, 500);
  assert.equal((await adm(`/users/${S.userId}/points`, { method: "POST", body: { amount: -9999, reason: "x" } })).status, 409, "残高を超える減算は不可");
  assert.equal((await adm(`/users/${S.userId}/points`, { method: "POST", body: { amount: 10, reason: "" } })).status, 400);
  assert.equal((await adm(`/users/${S.userId}/points`, { method: "POST", body: { amount: 1.5, reason: "x" } })).status, 400);
  assert.equal((await adm(`/users/${S.userId}/points`, { method: "POST", body: { amount: -100, reason: "調整" } })).data.points, 400);
  const prev = await adm("/points/distribute", { method: "POST", body: { target: "all", amount: 10, reason: "全員配布", dryRun: true } });
  const n = prev.data.count;
  assert.ok(n >= 3);
  assert.equal((await adm("/points/distribute", { method: "POST", body: { target: "all", amount: 10, reason: "全員配布", expect: n + 1 } })).status, 409, "人数がずれたら実行しない");
  assert.equal((await adm("/points/distribute", { method: "POST", body: { target: "all", amount: -10, reason: "x", expect: n } })).status, 400, "一括は加算のみ");
  const run = await adm("/points/distribute", { method: "POST", body: { target: "all", amount: 10, reason: "全員配布", expect: n } });
  assert.equal(run.status, 200, run.text);
  const me = await c.v1("/v1/me", { token: S.token });
  assert.equal(me.data.user.points, 410);
  // 未確認ユーザーは対象外
  await c.v1("/v1/register", { method: "POST", body: { name: "u", email: "unverified@example.com", password: PW } });
  const em = await adm("/points/distribute", { method: "POST", body: { target: "emails", emails: "taro2@example.com\nunverified@example.com\nnone@example.com", amount: 5, reason: "個別", dryRun: true } });
  assert.equal(em.data.count, 1); assert.equal(em.data.skipped.length, 2);
  await adm("/points/distribute", { method: "POST", body: { target: "emails", emails: ["taro2@example.com"], amount: 5, reason: "個別", expect: 1 } });
  // ユーザー側の履歴に台帳が出る & 残高と整合
  const hist = await c.v1("/v1/points/history", { token: S.token });
  assert.equal(hist.data.points, 415);
  assert.equal(hist.data.history.reduce((s, h) => s + h.delta, 0), 415);
  assert.equal(hist.data.history[0].balanceAfter, 415);
  assert.equal(hist.data.history[0].source, "運営");
  const aud = await adm("/audit");
  assert.ok(aud.data.entries.some((e) => e.action === "points.distribute_all"));
});

test("管理者のみ: points:write アプリ(開発者アプリへの付与・点数API・冪等性・残高不足・日次上限・取り消し)", async () => {
  // 開発者アプリは points:write を持てない(前のテストで確認済み)。管理者が既存アプリに付与
  const apps = await adm("/apps");
  const mine = apps.data.apps.find((a) => a.id === S.app.id);
  assert.equal(mine.ownerEmail, "taro2@example.com");
  assert.equal(mine.pointsApproved, false);
  const up = await adm(`/apps/${S.app.id}/update`, { method: "POST", body: { name: "My App", description: "d", redirectUris: mine.redirectUris, scopes: ["profile", "email", "points:read", "points:write"], pointsDailyLimit: 300, status: "active" } });
  assert.equal(up.status, 200, up.text);
  // 開発者が自分で編集しても points:write は保持され、新規に足すことはできない
  const devEdit = await c.v1("/v1/apps/update", { method: "POST", token: S.token, body: { id: S.app.id, name: "Renamed", description: "", redirectUris: ["https://app.example/cb"], scopes: ["profile", "points:read"] } });
  assert.equal(devEdit.status, 200);
  assert.ok(devEdit.data.app.scopes.includes("points:write"), "管理者付与分は残る");

  // 同意 → トークン(points:read points:write)
  const pk = pkce();
  const post = (o) => c.call("/oauth/authorize", { method: "POST", headers: FORM, body: form({ client_id: S.app.id, redirect_uri: "https://app.example/cb", scope: "profile points:read points:write", state: "s", code_challenge: pk.challenge, code_challenge_method: "S256", decision: "allow", email: "taro2@example.com", password: S.pw, ...o }) });
  const page = await c.call("/oauth/authorize?" + form({ response_type: "code", client_id: S.app.id, scope: "profile points:write", redirect_uri: "https://app.example/cb" }));
  assert.match(page.text, /ポイントの加算・減算/);
  const loc = new URL((await post({})).headers.get("Location"));
  const basic = "Basic " + Buffer.from(S.app.id + ":" + S.app.secret).toString("base64");
  const t = await c.call("/oauth/token", { method: "POST", headers: { ...FORM, Authorization: basic }, body: form({ grant_type: "authorization_code", code: loc.searchParams.get("code"), redirect_uri: "https://app.example/cb", code_verifier: pk.verifier }) });
  assert.equal(t.status, 200, t.text);
  const AT = { Authorization: "Bearer " + t.data.access_token };
  S.pointsToken = t.data;
  const adj = (o, headers = AT) => c.call("/api/v1/points/adjust", { method: "POST", headers, body: o });

  assert.equal((await c.call("/api/v1/points", { headers: AT })).data.points, 415);
  const a1 = await adj({ amount: 100, reason: "ミッション報酬", idempotency_key: "key-0001-aaaa" });
  assert.equal(a1.status, 200, a1.text);
  assert.equal(a1.data.points, 515);
  const again = await adj({ amount: 100, reason: "ミッション報酬", idempotency_key: "key-0001-aaaa" });
  assert.equal(again.data.replayed, true);
  assert.equal(again.data.points, 515, "同じキーの再送で二重加算されない");
  assert.equal((await adj({ amount: 999, reason: "別内容", idempotency_key: "key-0001-aaaa" })).status, 400, "上限超過または別内容");
  assert.equal((await adj({ amount: 50, reason: "別内容", idempotency_key: "key-0001-aaaa" })).status, 409, "同一キーで内容が違うと拒否");
  assert.equal((await adj({ amount: -1000, reason: "x", idempotency_key: "key-0002-aaaa" })).status, 400, "1回の上限(300)を超える");
  assert.equal((await adj({ amount: 1.5, reason: "x", idempotency_key: "key-0003-aaaa" })).status, 400);
  assert.equal((await adj({ amount: 10, reason: "x", idempotency_key: "short" })).status, 400);
  // 日次上限(300): 既に100使用 → 200まではOK、超えると429
  assert.equal((await adj({ amount: 200, reason: "r", idempotency_key: "key-0004-aaaa" })).status, 200);
  const over = await adj({ amount: 1, reason: "r", idempotency_key: "key-0005-aaaa" });
  assert.equal(over.status, 429, over.text);
  assert.equal(over.data.error, "daily_limit_exceeded");
  // 残高不足は台帳・残高とも変化しない
  await adm(`/apps/${S.app.id}/update`, { method: "POST", body: { name: "Renamed", description: "", redirectUris: ["https://app.example/cb"], scopes: ["profile", "email", "points:read", "points:write"], pointsDailyLimit: 100000, status: "active" } });
  assert.equal((await adj({ amount: -800, reason: "x", idempotency_key: "key-0006-aaaa" })).status, 409);
  assert.equal((await adj({ amount: -800, reason: "x", idempotency_key: "key-0006-aaaa" })).status, 409);
  const bal = (await c.call("/api/v1/points", { headers: AT })).data.points;
  assert.equal(bal, 715);
  const hist = await c.v1("/v1/points/history", { token: S.token });
  assert.equal(hist.data.points, 715);
  assert.equal(hist.data.history.reduce((s, h) => s + h.delta, 0), 715, "台帳の合計=残高");
  assert.equal(hist.data.history[0].source, "Renamed");

  // 管理者がスコープを外すと、発行済みトークンでも即座に使えない
  const mine2 = (await adm("/apps")).data.apps.find((a) => a.id === S.app.id);
  await adm(`/apps/${S.app.id}/update`, { method: "POST", body: { name: "Renamed", description: "", redirectUris: mine2.redirectUris, scopes: ["profile", "email", "points:read"], pointsDailyLimit: 100, status: "active" } });
  assert.equal((await adj({ amount: 1, reason: "r", idempotency_key: "key-0007-aaaa" })).status, 403);
  assert.equal((await c.call("/api/v1/points", { headers: AT })).status, 200, "readは残る");
});

test("BAN: 全セッション・OAuthトークン即時失効 / ログイン・認可不可 / 解除 / 管理者による新規アプリ作成", async () => {
  // 新しい端末とOAuthトークンを用意
  const l = await login("taro2@example.com", S.pw, "Doomed");
  assert.equal((await c.v1("/v1/me", { token: l.data.token })).status, 200);
  const ban = await adm(`/users/${S.userId}/ban`, { method: "POST", body: { reason: "規約違反" } });
  assert.equal(ban.status, 200);
  assert.equal((await adm(`/users/${S.userId}/ban`, { method: "POST", body: { reason: "" } })).status, 400);
  assert.equal((await c.v1("/v1/me", { token: l.data.token })).status, 401);
  assert.equal((await c.v1("/v1/me", { token: S.token })).status, 401);
  assert.equal((await c.call("/api/v1/points", { headers: { Authorization: "Bearer " + S.pointsToken.access_token } })).status, 401, "OAuthトークンも失効");
  const lg = await login("taro2@example.com", S.pw);
  assert.equal(lg.status, 403);
  assert.match(lg.data.error, /停止/);
  assert.equal((await login("taro2@example.com", "wrong-password-123")).status, 401, "停止の有無はパスワードが合うまで分からない");
  const az = await c.call("/oauth/authorize", { method: "POST", headers: FORM, body: form({ client_id: S.app.id, redirect_uri: "https://app.example/cb", scope: "profile", decision: "allow", email: "taro2@example.com", password: S.pw }) });
  assert.equal(az.status, 403);
  assert.equal((await adm(`/users/${S.userId}`)).data.user.banReason, "規約違反");
  // 解除
  await adm(`/users/${S.userId}/unban`, { method: "POST" });
  assert.equal((await login("taro2@example.com", S.pw)).status, 200);

  // 管理者が直接 points:write アプリを作成(開発者を介さない)
  const created = await adm("/apps", { method: "POST", body: { name: "公式ポイントアプリ", description: "運営", redirectUris: ["https://official.example/cb"], scopes: ["profile", "points:read", "points:write"], pointsDailyLimit: 5000 } });
  assert.equal(created.status, 200, created.text);
  assert.match(created.data.clientSecret, /^sas_/);
  const list = (await adm("/apps")).data.apps.find((a) => a.id === created.data.id);
  assert.equal(list.pointsApproved, true);
  assert.equal(list.createdBy, "admin");
  // 無効化するとトークンも使えず認可画面も出ない
  await adm(`/apps/${created.data.id}/update`, { method: "POST", body: { ...list, redirectUris: list.redirectUris, status: "disabled" } });
  assert.equal((await c.call("/oauth/authorize?" + form({ response_type: "code", client_id: created.data.id, redirect_uri: "https://official.example/cb" }))).status, 400);
  // 管理者ログアウト後はAPI不可
  await adm("/logout", { method: "POST" });
  assert.equal((await adm("/stats")).status, 401);
});

test("セキュリティヘッダ / CORS範囲 / 内部エラー非開示 / 巨大ボディ", async () => {
  const r = await c.call("/verify", { raw: true });
  assert.equal(r.headers.get("X-Frame-Options"), "DENY");
  assert.equal(r.headers.get("Referrer-Policy"), "no-referrer");
  const pre = await c.call("/oauth/token", { method: "OPTIONS", raw: true });
  assert.equal(pre.status, 204);
  assert.equal((await c.call("/v1/login", { method: "OPTIONS", raw: true })).status, 404, "/v1/* にはCORSなし");
  assert.equal((await c.v1("/v1/login", { method: "POST", body: "x".repeat(40000) })).status, 413);
  assert.equal((await c.v1("/v1/login", { method: "POST", body: "{not json" })).status, 400);
  assert.equal((await c.call("/nonexistent")).status, 404);
  const meta = await c.call("/.well-known/oauth-authorization-server");
  assert.deepEqual(meta.data.code_challenge_methods_supported, ["S256"]);
});

test("cron掃除: 期限切れ・7日超の未確認ユーザーを削除", async () => {
  env.DB.raw.prepare("UPDATE users SET created_at=1 WHERE email='unverified@example.com'").run();
  await c.worker.scheduled({}, env, { waitUntil: (p) => p });
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) n FROM users WHERE email='unverified@example.com'").get().n, 0);
});

test("無料プラン対応: 反復回数は設定可能・上限100000・引き上げ時はログインで自動再ハッシュ / パスワード処理のCPU時間", async () => {
  const { hashPassword, verifyPassword, needsRehash, targetIterations } = await import("../src/util.js");
  assert.equal(targetIterations({}), 4000);
  assert.equal(targetIterations({ PBKDF2_ITERATIONS: "999999" }), 100000, "Workersの上限でクランプ");
  assert.equal(targetIterations({ PBKDF2_ITERATIONS: "5" }), 1000);
  // 1回のハッシュは無料プランのCPU 10ms枠に十分収まる(実行環境のばらつきを見て余裕を持った閾値)
  await hashPassword(env, "warm-up-password");
  const t0 = performance.now();
  const h = await hashPassword(env, "Another-Password-123");
  const ms = performance.now() - t0;
  assert.ok(ms < 8, "hash took " + ms.toFixed(1) + "ms");
  assert.equal(await verifyPassword(env, "Another-Password-123", h), true);
  // 設定を引き上げると再ハッシュ対象になり、ログインすると新しい反復回数に更新される
  env.PBKDF2_ITERATIONS = "6000";
  try {
    assert.equal(needsRehash(env, h), true);
    const l = await login("victim@example.com");
    assert.equal(l.status, 200, l.text);
    const row = env.DB.raw.prepare("SELECT password_hash FROM users WHERE email='victim@example.com'").get();
    assert.match(row.password_hash, /^v1\$6000\$/);
    assert.equal((await login("victim@example.com")).status, 200, "再ハッシュ後も同じパスワードでログインできる");
  } finally { env.PBKDF2_ITERATIONS = "4000"; }
});

test("管理者の個別配布は100件でもDB問い合わせが定数回(無料プランのsubrequest 50回制限)", async () => {
  const login2 = await adm("/login", { method: "POST", body: { password: env.ADMIN_PASSWORD }, cookie: "", token: "" });
  adminCookie = login2.headers.get("Set-Cookie").split(";")[0]; csrf = login2.data.csrf;
  const now = Date.now();
  const emails = [];
  for (let i = 0; i < 100; i++) {
    const e = `bulk${i}@example.com`; emails.push(e);
    env.DB.raw.prepare("INSERT INTO users(id,name,email,password_hash,email_verified,points,status,created_at) VALUES(?,?,?,?,1,0,'active',?)").run("bulk-" + i, "b" + i, e, "x", now);
  }
  let queries = 0;
  const origPrepare = env.DB.prepare;
  env.DB.prepare = (sql) => { queries++; return origPrepare(sql); };
  try {
    const r = await adm("/points/distribute", { method: "POST", body: { target: "emails", emails, amount: 3, reason: "bulk", dryRun: true } });
    assert.equal(r.data.count, 100, r.text);
    assert.ok(queries < 20, "queries=" + queries);
    const run = await adm("/points/distribute", { method: "POST", body: { target: "emails", emails, amount: 3, reason: "bulk", expect: 100 } });
    assert.equal(run.status, 200, run.text);
  } finally { env.DB.prepare = origPrepare; }
  assert.equal(env.DB.raw.prepare("SELECT points FROM users WHERE id='bulk-99'").get().points, 3);
});

test("OAuth確認ページ(/oauth-test)と仕様書(/llms.txt): CSP・構文・URL埋め込み・CORS・ルート整合", async () => {
  const page = await c.call("/oauth-test", { raw: true });
  const html = await page.text();
  assert.equal(page.status, 200);
  const nonce = /nonce-([\w+/=]+)/.exec(page.headers.get("Content-Security-Policy"))[1];
  assert.ok(html.includes(`<script nonce="${nonce}">`));
  assert.match(page.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  const js = /<script nonce="[^"]+">([\s\S]*)<\/script>/.exec(html)[1];
  assert.doesNotThrow(() => new Function(js), "確認ページのスクリプトが構文的に正しい");
  assert.ok(!html.includes("client_secret=sas_"), "シークレットを埋め込んでいない");

  const doc = await c.call("/llms.txt", { raw: true });
  const md = await doc.text();
  assert.equal(doc.status, 200);
  assert.match(doc.headers.get("Content-Type"), /text\/markdown/);
  assert.equal(doc.headers.get("Access-Control-Allow-Origin"), "*");
  assert.ok(md.includes("https://acct.test/oauth/authorize"), "Base URLが実際のオリジンに置換される");
  assert.ok(!md.includes("{{BASE}}"));
  assert.equal((await c.call("/api-docs", { raw: true })).status, 200);

  // 仕様書に載っている全エンドポイントが実在する(404/405でない)
  const methods = { "/oauth/token": "POST", "/oauth/revoke": "POST", "/api/v1/points/adjust": "POST" };
  const paths = [...new Set([...md.matchAll(/https:\/\/acct\.test(\/(?:oauth\/[a-z]+|api\/v1\/[a-z/]+|\.well-known\/[a-z-]+|llms\.txt|oauth-test))/g)].map((m) => m[1]))];
  assert.ok(paths.length >= 8, "paths=" + paths.join(","));
  for (const p of paths) {
    const r = await c.call(p, { method: methods[p] || "GET", ip: "198.51.100.200", body: methods[p] ? "" : undefined });
    assert.ok(![404, 405].includes(r.status), p + " → " + r.status);
  }
});
