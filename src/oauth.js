// OAuth 2.0 認可サーバー(認可コード + PKCE)と、外部アプリ向けリソースAPI
//
//   GET/POST /oauth/authorize   ログイン+同意画面(ブラウザで直接開く)
//   POST     /oauth/token       code / refresh_token の交換
//   POST     /oauth/revoke      トークン失効
//   GET      /oauth/userinfo    (= /api/v1/me) ユーザー情報(スコープに応じた項目)
//   GET      /api/v1/points     残高            (points:read または points:write)
//   POST     /api/v1/points/adjust  加算/減算  (points:write = 管理者承認済みアプリのみ)
import {
  HttpError, json, readText, readJson, readParams, normEmail, cleanText, randomToken, sha256, safeEqual, uuid,
  verifyPassword, hashPassword, limited, peek, hit, tooMany, clientIp, parseScopes, SCOPES,
} from "./util.js";
import { bearer, authSession } from "./session.js";
import { authorizePage, messagePage } from "./pages.js";
import { baseUrl } from "./mail.js";

const ACCESS_TTL = 3600;               // 1時間
const REFRESH_TTL = 30 * 86400;        // 30日
const CODE_TTL = 600;                  // 10分
const oerr = (status, error, desc, headers = {}) => json({ error, error_description: desc }, status, headers);

const intersect = (a, b) => parseScopes(a).filter((s) => parseScopes(b).includes(s));

// ---------------- /oauth/authorize ----------------
async function validateAuth(env, p) {
  const client = p.client_id && p.client_id.length < 80
    ? await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=? AND status='active'").bind(p.client_id).first() : null;
  if (!client) return { fatal: "アプリが見つからないか、無効化されています。" };
  const uris = JSON.parse(client.redirect_uris);
  const redirect = p.redirect_uri || (uris.length === 1 ? uris[0] : null);
  if (!redirect || !uris.includes(redirect)) return { fatal: "リダイレクトURIがアプリに登録されていません。" };
  const fail = (error, desc) => ({ client, redirect, error, desc });
  if (p.response_type !== "code" && p.decision === undefined) return fail("unsupported_response_type", "response_type=code のみ対応しています");
  let scopes = parseScopes(p.scope);
  if (!scopes.length) scopes = ["profile"];
  const allowed = parseScopes(client.scopes);
  const unknown = scopes.filter((s) => !allowed.includes(s));
  if (unknown.length) return fail("invalid_scope", "許可されていないスコープです: " + unknown.join(" "));
  if (p.code_challenge) {
    if (p.code_challenge_method !== "S256") return fail("invalid_request", "code_challenge_method は S256 のみ対応しています");
    if (!/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge)) return fail("invalid_request", "code_challenge が不正です");
  }
  return { client, redirect, scopes };
}

function redirectTo(env, uri, params) {
  const u = new URL(uri);
  u.searchParams.delete("iss");
  for (const [k, v] of Object.entries(params)) if (v != null && v !== "") u.searchParams.set(k, v);
  // OAuth 2.0 Authorization Server Issuer Identification (RFC 9207) is intentionally omitted for compatibility with clients that expect only code/state.
  return new Response(null, { status: 303, headers: { Location: u.toString(), "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
}

async function authorize(req, env) {
  const ip = clientIp(req);
  const isPost = req.method === "POST";
  const p = isPost ? Object.fromEntries(new URLSearchParams(await readText(req))) : Object.fromEntries(new URL(req.url).searchParams);
  for (const k of Object.keys(p)) p[k] = String(p[k]).slice(0, 600);

  const lim = await limited(env, [["authz-ip", ip, isPost ? 30 : 120, 600]]);
  if (lim) return messagePage("しばらくお待ちください", "アクセスが多すぎます。少し待ってからお試しください。", { status: 429 });

  const v = await validateAuth(env, p);
  if (v.fatal) return messagePage("リクエストが無効です", v.fatal, { status: 400 });
  if (v.error) return redirectTo(env, v.redirect, { error: v.error, error_description: v.desc, state: p.state }); // redirect_uri は検証済み
  const { client, redirect, scopes } = v;
  const echo = { client_id: client.id, redirect_uri: redirect, scope: scopes.join(" "), state: p.state, code_challenge: p.code_challenge, code_challenge_method: p.code_challenge_method };

  if (!isPost) return authorizePage({ client, scopes, params: echo });

  if (p.decision === "deny") return redirectTo(env, redirect, { error: "access_denied", error_description: "ユーザーが拒否しました", state: p.state });
  if (p.decision !== "allow" && p.decision !== "allow_session") return messagePage("リクエストが無効です", "操作が不正です。", { status: 400 });

  let u = null;
  if (p.decision === "allow_session") {
    const sessionToken = String(p.session_token || "");
    if (!/^ses_[A-Za-z0-9_-]{20,80}$/.test(sessionToken)) return messagePage("ログイン状態を確認できません", "もう一度ログインしてください。", { status: 401 });
    const sessionReq = new Request(new URL(req.url).toString(), { headers: { Authorization: "Bearer " + sessionToken } });
    const auth = await authSession(sessionReq, env);
    if (!auth || auth.user.email_verified !== 1) return messagePage("ログイン状態を確認できません", "もう一度ログインしてください。", { status: 401 });
    u = auth.user;
  } else {
    const email = normEmail(p.email);
    const show = (msg, status = 401) => { const r = authorizePage({ client, scopes, params: echo, error: msg, email: email || "" }); return new Response(r.body, { status, headers: r.headers }); };
    if (!email || !p.password) return show("メールアドレスとパスワードを入力してください");
    const r = await peek(env, "login-fail", email, 10, 900); // /v1/login と同じ「失敗回数」カウンタを共有
    if (r) return show(tooMany(r).message, 429);
    u = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    const ok = u ? await verifyPassword(env, p.password.slice(0, 200), u.password_hash) : (await hashPassword(env, p.password), false);
    if (!ok) { await hit(env, "login-fail", email, 10, 900); return show("メールアドレスまたはパスワードが正しくありません"); }
    if (u.status !== "active") return show("このアカウントは利用停止されています", 403);
    if (!u.email_verified) return show("メールアドレスの確認が完了していません", 403);
  }

  const code = "sac_" + randomToken(32), now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,scopes,code_challenge,expires_at) VALUES(?,?,?,?,?,?,?)")
      .bind(await sha256(code), client.id, u.id, redirect, scopes.join(" "), p.code_challenge || null, now + CODE_TTL * 1000),
    env.DB.prepare(
      `INSERT INTO oauth_grants(user_id,client_id,scopes,created_at,updated_at) VALUES(?1,?2,?3,?4,?4)
       ON CONFLICT(user_id,client_id) DO UPDATE SET scopes=?3, updated_at=?4`
    ).bind(u.id, client.id, scopes.join(" "), now),
  ]);
  return redirectTo(env, redirect, { code, state: p.state });
}

// ---------------- /oauth/token ----------------
async function clientAuth(req, env, p) {
  let id = p.client_id, secret = p.client_secret;
  const basic = /^Basic\s+(\S+)$/i.exec(req.headers.get("Authorization") || "");
  if (basic) {
    try {
      const raw = atob(basic[1]); const i = raw.indexOf(":");
      id = decodeURIComponent(raw.slice(0, i)); secret = decodeURIComponent(raw.slice(i + 1));
    } catch { return null; }
  }
  if (!id || !secret || String(id).length > 80) return null;
  const c = await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=?").bind(String(id)).first();
  const ok = await safeEqual(await sha256(String(secret)), c ? c.secret_hash : "x");
  return c && ok && c.status === "active" ? c : null;
}

async function issueTokens(env, client, userId, scopes) {
  const access = "sat_" + randomToken(32), refresh = "srt_" + randomToken(32), now = Date.now();
  await env.DB.batch([
    // 同一ユーザー×アプリのトークンは新しい4件だけ残す(+今回の1件=最大5件)
    env.DB.prepare("DELETE FROM oauth_tokens WHERE user_id=?1 AND client_id=?2 AND id NOT IN (SELECT id FROM oauth_tokens WHERE user_id=?1 AND client_id=?2 ORDER BY created_at DESC LIMIT 4)").bind(userId, client.id),
    env.DB.prepare("INSERT INTO oauth_tokens(id,access_hash,refresh_hash,client_id,user_id,scopes,access_expires,refresh_expires,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(uuid(), await sha256(access), await sha256(refresh), client.id, userId, scopes, now + ACCESS_TTL * 1000, now + REFRESH_TTL * 1000, now),
  ]);
  return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refresh, scope: scopes }, 200, { Pragma: "no-cache" });
}

async function token(req, env) {
  const ip = clientIp(req);
  const lim = await limited(env, [["token-ip", ip, 120, 60]]);
  if (lim) return oerr(429, "temporarily_unavailable", "リクエストが多すぎます", { "Retry-After": String(lim.retryAfter) });
  const p = await readParams(req);
  const client = await clientAuth(req, env, p);
  if (!client) return oerr(401, "invalid_client", "クライアント認証に失敗しました", { "WWW-Authenticate": 'Basic realm="oauth"' });
  const lim2 = await limited(env, [["token-client", client.id, 300, 60]]);
  if (lim2) return oerr(429, "temporarily_unavailable", "リクエストが多すぎます", { "Retry-After": String(lim2.retryAfter) });

  const now = Date.now();
  if (p.grant_type === "authorization_code") {
    const row = await env.DB.prepare("DELETE FROM oauth_codes WHERE code_hash=? RETURNING *").bind(await sha256(String(p.code || ""))).first(); // 1回限り
    const bad = () => oerr(400, "invalid_grant", "認可コードが無効、期限切れ、または使用済みです");
    if (!row || row.client_id !== client.id || row.expires_at < now) return bad();
    const uris = JSON.parse(client.redirect_uris);
    const given = p.redirect_uri || (uris.length === 1 ? uris[0] : "");
    if (given !== row.redirect_uri) return bad();
    if (row.code_challenge) {
      const vf = String(p.code_verifier || "");
      if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(vf) || !(await safeEqual(await sha256(vf), row.code_challenge))) return bad();
    }
    const u = await env.DB.prepare("SELECT status FROM users WHERE id=?").bind(row.user_id).first();
    const scopes = intersect(row.scopes, client.scopes).join(" ");
    if (!u || u.status !== "active" || !scopes) return bad();
    return issueTokens(env, client, row.user_id, scopes);
  }
  if (p.grant_type === "refresh_token") {
    const row = await env.DB.prepare("DELETE FROM oauth_tokens WHERE refresh_hash=? AND client_id=? RETURNING *").bind(await sha256(String(p.refresh_token || "")), client.id).first(); // ローテーション
    if (!row || row.refresh_expires < now) return oerr(400, "invalid_grant", "リフレッシュトークンが無効または期限切れです");
    const u = await env.DB.prepare("SELECT status FROM users WHERE id=?").bind(row.user_id).first();
    const scopes = intersect(row.scopes, client.scopes).join(" ");
    if (!u || u.status !== "active" || !scopes) return oerr(400, "invalid_grant", "リフレッシュトークンが無効です");
    return issueTokens(env, client, row.user_id, scopes);
  }
  return oerr(400, "unsupported_grant_type", "authorization_code または refresh_token を指定してください");
}

async function revoke(req, env) {
  const lim = await limited(env, [["token-ip", clientIp(req), 120, 60]]);
  if (lim) return oerr(429, "temporarily_unavailable", "リクエストが多すぎます");
  const p = await readParams(req);
  const client = await clientAuth(req, env, p);
  if (!client) return oerr(401, "invalid_client", "クライアント認証に失敗しました");
  const h = await sha256(String(p.token || ""));
  await env.DB.prepare("DELETE FROM oauth_tokens WHERE (access_hash=?1 OR refresh_hash=?1) AND client_id=?2").bind(h, client.id).run();
  return json({}); // RFC 7009: 常に200
}

// ---------------- リソースAPI(Bearerアクセストークン) ----------------
async function authBearer(req, env) {
  const t = bearer(req);
  if (!t.startsWith("sat_") || t.length > 100) return null;
  const r = await env.DB.prepare(
    `SELECT t.scopes AS tscopes, t.access_expires, t.client_id, c.scopes AS cscopes, c.status AS cstatus, c.points_daily_limit,
            u.id AS uid, u.name, u.email, u.email_verified, u.points, u.status AS ustatus
     FROM oauth_tokens t JOIN oauth_clients c ON c.id=t.client_id JOIN users u ON u.id=t.user_id WHERE t.access_hash=?`
  ).bind(await sha256(t)).first();
  if (!r || r.access_expires <= Date.now() || r.cstatus !== "active" || r.ustatus !== "active") return null;
  // 管理者が後からスコープを外した場合に即時反映されるよう、クライアントの現スコープとの積集合を使う
  return { clientId: r.client_id, scopes: intersect(r.tscopes, r.cscopes), limit: r.points_daily_limit, user: { id: r.uid, name: r.name, email: r.email, emailVerified: !!r.email_verified, points: r.points } };
}
const need = (a, ...any) => { if (!any.some((s) => a.scopes.includes(s))) throw new HttpError(403, "insufficient_scope: " + any.join(" または ") + " が必要です", { oauth: "insufficient_scope" }); };

function userinfo(a) {
  const out = { sub: a.user.id };
  if (a.scopes.includes("profile")) out.name = a.user.name;
  if (a.scopes.includes("email")) { out.email = a.user.email; out.email_verified = a.user.emailVerified; }
  if (a.scopes.includes("points:read") || a.scopes.includes("points:write")) out.points = a.user.points;
  return out;
}

async function adjustPoints(req, env, a) {
  need(a, "points:write");
  const b = await readJson(req);
  const amount = b.amount, reason = cleanText(b.reason, 100), idem = String(b.idempotency_key || "");
  if (!Number.isInteger(amount) || amount === 0) throw new HttpError(400, "amount は 0 以外の整数で指定してください");
  if (Math.abs(amount) > a.limit) throw new HttpError(400, `1回の増減は ${a.limit} ポイントまでです`);
  if (!reason) throw new HttpError(400, "reason が必要です");
  if (!/^[A-Za-z0-9_.:-]{8,64}$/.test(idem)) throw new HttpError(400, "idempotency_key(8〜64文字の英数字と _ . : -)が必要です");
  const lim = await limited(env, [["points-client", a.clientId, 600, 60]]);
  if (lim) throw tooMany(lim);

  const replay = async () => {
    const ex = await env.DB.prepare("SELECT id,user_id,delta,balance_after FROM point_ledger WHERE actor=? AND idem_key=?").bind(a.clientId, idem).first();
    if (!ex) return null;
    if (ex.user_id !== a.user.id || ex.delta !== amount) throw new HttpError(409, "同じ idempotency_key が別の内容で使われています");
    return json({ ok: true, replayed: true, points: ex.balance_after, ledger_id: ex.id });
  };
  const prior = await replay();
  if (prior) return prior;

  const id = uuid(), now = Date.now();
  let res;
  try {
    res = await env.DB.batch([
      // 残高不足・24時間上限・BAN を SQL の条件で原子的に判定
      env.DB.prepare(
        `UPDATE users SET points = points + ?1 WHERE id = ?2 AND status = 'active' AND points + ?1 >= 0
           AND (SELECT COALESCE(SUM(ABS(delta)),0) FROM point_ledger WHERE actor = ?3 AND created_at > ?4) + ABS(?1) <= ?5`
      ).bind(amount, a.user.id, a.clientId, now - 86400000, a.limit),
      env.DB.prepare(
        `INSERT INTO point_ledger(id,user_id,delta,balance_after,reason,source,actor,idem_key,created_at)
         SELECT ?1, id, ?2, points, ?3, 'app', ?4, ?5, ?6 FROM users WHERE id = ?7 AND changes() > 0`
      ).bind(id, amount, reason, a.clientId, idem, now, a.user.id),
    ]);
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) { const r = await replay(); if (r) return r; }
    throw e;
  }
  if (res[0].meta.changes === 0) {
    const cur = await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(a.user.id).first();
    if (cur && amount < 0 && cur.points + amount < 0) throw new HttpError(409, "ポイント残高が不足しています", { oauth: "insufficient_points", points: cur.points });
    const used = await env.DB.prepare("SELECT COALESCE(SUM(ABS(delta)),0) AS n FROM point_ledger WHERE actor=? AND created_at>?").bind(a.clientId, now - 86400000).first();
    throw new HttpError(429, "このアプリの24時間あたりのポイント増減上限に達しました", { oauth: "daily_limit_exceeded", used: used.n, limit: a.limit });
  }
  const row = await env.DB.prepare("SELECT balance_after FROM point_ledger WHERE id=?").bind(id).first();
  return json({ ok: true, points: row.balance_after, ledger_id: id });
}

export async function handleApi(req, env, path) {
  const a = await authBearer(req, env);
  if (!a) return json({ error: "invalid_token", error_description: "アクセストークンが無効または期限切れです" }, 401, { "WWW-Authenticate": 'Bearer error="invalid_token"' });
  try {
    if ((path === "/api/v1/me" || path === "/oauth/userinfo") && req.method === "GET") return json(userinfo(a));
    if (path === "/api/v1/points" && req.method === "GET") { need(a, "points:read", "points:write"); return json({ ok: true, points: a.user.points }); }
    if (path === "/api/v1/points/adjust" && req.method === "POST") return await adjustPoints(req, env, a);
  } catch (e) {
    if (e instanceof HttpError) return json({ ok: false, error: e.extra.oauth || "error", error_description: e.message, ...e.extra }, e.status);
    throw e;
  }
  return json({ error: "not_found" }, 404);
}

export async function handleOAuth(req, env, path) {
  if (path === "/oauth/authorize") return authorize(req, env);
  if (path === "/oauth/token" && req.method === "POST") return token(req, env);
  if (path === "/oauth/revoke" && req.method === "POST") return revoke(req, env);
  if (path === "/oauth/userinfo" && req.method === "GET") return handleApi(req, env, path);
  if (path === "/.well-known/oauth-authorization-server") {
    const b = baseUrl(env);
    return json({
      issuer: b, authorization_endpoint: b + "/oauth/authorize", token_endpoint: b + "/oauth/token", revocation_endpoint: b + "/oauth/revoke",
      userinfo_endpoint: b + "/oauth/userinfo", scopes_supported: Object.keys(SCOPES), response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"], authorization_response_iss_parameter_supported: true,
    });
  }
  return null;
}
