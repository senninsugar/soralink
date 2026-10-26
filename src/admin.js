// 管理者パネル: /admin (画面) と /admin/api/* (API)
//
// - 認証は環境変数 ADMIN_PASSWORD(Workerシークレット)のみ。ユーザーアカウントのロール昇格では入れません。
// - ログイン成功で HttpOnly + Secure + SameSite=Strict の Cookie セッションを発行(2時間・DBで失効可能)。
// - 変更系APIは CSRFトークン(ヘッダ) と Origin 検証を必須にしています。
// - ブルートフォース対策: IPごと 5回/15分、全体で失敗30回/時間でロック。操作は全て admin_audit に記録。
import {
  HttpError, json, readJson, safeEqual, sha256, randomToken, uuid, limited, peek, hit, tooMany, clientIp,
  normEmail, cleanText, audit,
} from "./util.js";
import { revokeAccess } from "./session.js";
import { SECURITY_HEADERS } from "./pages.js";
import { adminHtml } from "./admin_ui.js";
import { cleanRedirects, adminScopes, insertClient, rotateSecret, publicClient, deleteClient } from "./apps.js";
import { sendPasswordReset } from "./users.js";

const ADMIN_TTL = 2 * 3600 * 1000;
const MAX_POINTS = 1000000;
const bad = (m, s = 400) => new HttpError(s, m);

export const adminEnabled = (env) => typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length >= 12;
const isHttps = (req) => new URL(req.url).protocol === "https:";
const cookieName = (req) => (isHttps(req) ? "__Host-sa_admin" : "sa_admin");
function getCookie(req, name) {
  for (const part of (req.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
}
const setCookie = (req, value, maxAge) =>
  `${cookieName(req)}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isHttps(req) ? "; Secure" : ""}`;

async function currentSession(req, env, proxy = false) {
  // ブラウザは Cookie、GAS 中継は X-Admin-Token ヘッダ(APP_KEY を通過したサーバー間呼び出しのみ)
  const t = proxy ? req.headers.get("X-Admin-Token") || "" : getCookie(req, cookieName(req));
  if (!t || t.length > 100) return null;
  const s = await env.DB.prepare("SELECT * FROM admin_sessions WHERE token_hash=? AND expires_at>?").bind(await sha256(t), Date.now()).first();
  return s || null;
}

async function login(req, env, proxy = false) {
  const ip = proxy ? "gas-proxy" : clientIp(req);
  const lock = (await peek(env, "admin-fail-all", "*", 30, 3600)) || (await peek(env, "admin-fail-ip", ip, 5, 900));
  if (lock) throw tooMany(lock);
  const b = await readJson(req);
  if (!(await safeEqual(String(b.password || "").slice(0, 200), env.ADMIN_PASSWORD))) {
    await hit(env, "admin-fail-all", "*", 30, 3600);
    await hit(env, "admin-fail-ip", ip, 5, 900);
    await audit(env, req, "admin.login_failed");
    await new Promise((r) => setTimeout(r, 500)); // 軽い遅延
    throw bad("パスワードが正しくありません", 401);
  }
  const token = randomToken(32), csrf = randomToken(24), now = Date.now();
  await env.DB.prepare("INSERT INTO admin_sessions(id,token_hash,csrf,ip,created_at,expires_at) VALUES(?,?,?,?,?,?)")
    .bind(uuid(), await sha256(token), csrf, ip, now, now + ADMIN_TTL).run();
  await audit(env, req, "admin.login");
  if (proxy) return json({ ok: true, csrf, token });
  return json({ ok: true, csrf }, 200, { "Set-Cookie": setCookie(req, token, ADMIN_TTL / 1000) });
}

// ---------- points ----------
async function adjustOne(env, userId, amount, reason) {
  const id = uuid(), now = Date.now();
  const res = await env.DB.batch([
    env.DB.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2 AND points + ?1 >= 0").bind(amount, userId),
    env.DB.prepare("INSERT INTO point_ledger(id,user_id,delta,balance_after,reason,source,actor,idem_key,created_at) SELECT ?1,id,?2,points,?3,'admin','admin',NULL,?4 FROM users WHERE id=?5 AND changes()>0")
      .bind(id, amount, reason, now, userId),
  ]);
  if (res[0].meta.changes === 0) {
    const u = await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(userId).first();
    if (!u) throw bad("ユーザーが見つかりません", 404);
    throw bad(`残高が不足しています(現在 ${u.points} pt)`, 409);
  }
  return (await env.DB.prepare("SELECT balance_after FROM point_ledger WHERE id=?").bind(id).first()).balance_after;
}
function pointArgs(b, { positiveOnly = false } = {}) {
  const amount = b.amount, reason = cleanText(b.reason, 100);
  if (!Number.isInteger(amount) || amount === 0 || Math.abs(amount) > MAX_POINTS) throw bad(`ポイントは 0 以外の整数(±${MAX_POINTS.toLocaleString()}以内)で指定してください`);
  if (positiveOnly && amount < 0) throw bad("一括配布は加算のみです");
  if (!reason) throw bad("理由を入力してください");
  return { amount, reason };
}

async function distribute(req, env) {
  const b = await readJson(req);
  const { amount, reason } = pointArgs(b, { positiveOnly: true });
  const now = Date.now();
  const ELIGIBLE = "status='active' AND email_verified=1";
  if (b.target === "all") {
    const n = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE ${ELIGIBLE}`).first()).n;
    if (b.dryRun) return json({ ok: true, count: n });
    if (b.expect !== n) throw bad(`対象人数が変わりました(現在 ${n} 人)。もう一度プレビューしてください`, 409);
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET points = points + ? WHERE ${ELIGIBLE}`).bind(amount),
      env.DB.prepare(`INSERT INTO point_ledger(id,user_id,delta,balance_after,reason,source,actor,idem_key,created_at)
        SELECT lower(hex(randomblob(16))), id, ?1, points, ?2, 'admin', 'admin', NULL, ?3 FROM users WHERE ${ELIGIBLE}`).bind(amount, reason, now),
    ]);
    await audit(env, req, "points.distribute_all", null, { amount, reason, count: n });
    return json({ ok: true, count: n, message: `${n}人に ${amount} pt を配布しました` });
  }
  if (b.target === "emails") {
    const emails = [...new Set((Array.isArray(b.emails) ? b.emails : String(b.emails || "").split(/[\s,;]+/)).map(normEmail).filter(Boolean))];
    if (!emails.length) throw bad("メールアドレスを指定してください");
    if (emails.length > 100) throw bad("一度に指定できるのは100件までです");
    // 無料プランは 1 リクエストあたり subrequest 50 回まで。1件ずつSELECTせず、1クエリで取得する
    const rows = await env.DB.prepare(`SELECT id,email FROM users WHERE ${ELIGIBLE} AND email IN (${emails.map(() => "?").join(",")})`).bind(...emails).all();
    const byEmail = new Map(rows.results.map((r) => [r.email, r.id]));
    const found = [], skipped = [];
    for (const e of emails) (byEmail.has(e) ? found.push({ id: byEmail.get(e), email: e }) : skipped.push(e));
    if (b.dryRun) return json({ ok: true, count: found.length, skipped });
    if (b.expect !== found.length) throw bad("対象人数が変わりました。もう一度プレビューしてください", 409);
    const stmts = [];
    for (const u of found) {
      stmts.push(env.DB.prepare("UPDATE users SET points = points + ? WHERE id=?").bind(amount, u.id));
      stmts.push(env.DB.prepare("INSERT INTO point_ledger(id,user_id,delta,balance_after,reason,source,actor,idem_key,created_at) SELECT lower(hex(randomblob(16))),id,?1,points,?2,'admin','admin',NULL,?3 FROM users WHERE id=?4").bind(amount, reason, now, u.id));
    }
    if (stmts.length) await env.DB.batch(stmts);
    await audit(env, req, "points.distribute_emails", null, { amount, reason, count: found.length, skipped: skipped.length });
    return json({ ok: true, count: found.length, skipped, message: `${found.length}人に ${amount} pt を配布しました` });
  }
  throw bad("target が不正です");
}

// ---------- full account deletion ----------
// ユーザーと、そのユーザーに紐づく全データを物理削除する(取り消し不可)。
// 外部キーのCASCADEに頼らず、対象テーブルを明示的に消す。
async function deleteUserFully(req, env, user) {
  const b = await readJson(req);
  if (normEmail(b.confirmEmail) !== user.email) throw bad("確認用のメールアドレスが一致しません。入力内容を確認してください");
  const uid = user.id;
  const ownedClients = "SELECT id FROM oauth_clients WHERE owner_user_id=?1";
  await env.DB.batch([
    // OAuth: このユーザーの開発アプリに紐づくトークン/コード/連携、およびユーザー自身の分
    env.DB.prepare(`DELETE FROM oauth_tokens WHERE user_id=?1 OR client_id IN (${ownedClients})`).bind(uid),
    env.DB.prepare(`DELETE FROM oauth_codes WHERE user_id=?1 OR client_id IN (${ownedClients})`).bind(uid),
    env.DB.prepare(`DELETE FROM oauth_grants WHERE user_id=?1 OR client_id IN (${ownedClients})`).bind(uid),
    env.DB.prepare("DELETE FROM oauth_clients WHERE owner_user_id=?1").bind(uid),
    // アカウント関連
    env.DB.prepare("DELETE FROM sessions WHERE user_id=?1").bind(uid),
    env.DB.prepare("DELETE FROM email_changes WHERE user_id=?1").bind(uid),
    env.DB.prepare("DELETE FROM email_tokens WHERE id=?1").bind(uid),
    env.DB.prepare("DELETE FROM email_codes WHERE email=?1").bind(user.email),
    env.DB.prepare("DELETE FROM point_ledger WHERE user_id=?1").bind(uid),
    env.DB.prepare("DELETE FROM users WHERE id=?1").bind(uid),
  ]);
  // 監査ログは管理者の操作記録として残す(対象メールは記録のため保持)
  await audit(env, req, "user.delete", user.email, { id: uid, name: user.name });
}

// ---------- routes ----------
async function route(req, env, path, s) {
  const m = req.method;
  let r;

  if (path === "/admin/api/stats" && m === "GET") {
    const now = Date.now();
    const one = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).first()).n;
    return json({
      ok: true,
      stats: {
        users: await one("SELECT COUNT(*) AS n FROM users"),
        verified: await one("SELECT COUNT(*) AS n FROM users WHERE email_verified=1"),
        banned: await one("SELECT COUNT(*) AS n FROM users WHERE status='banned'"),
        new24h: await one("SELECT COUNT(*) AS n FROM users WHERE created_at>?", now - 86400000),
        new7d: await one("SELECT COUNT(*) AS n FROM users WHERE created_at>?", now - 7 * 86400000),
        activeSessions: await one("SELECT COUNT(*) AS n FROM sessions WHERE expires_at>?", now),
        totalPoints: await one("SELECT COALESCE(SUM(points),0) AS n FROM users"),
        apps: await one("SELECT COUNT(*) AS n FROM oauth_clients"),
        pointsApps: await one("SELECT COUNT(*) AS n FROM oauth_clients WHERE (' '||scopes||' ') LIKE '% points:write %'"),
      },
    });
  }

  if (path === "/admin/api/users" && m === "GET") {
    const u = new URL(req.url).searchParams;
    const q = cleanText(u.get("q"), 100), status = u.get("status") || "", offset = Math.max(0, parseInt(u.get("offset") || "0", 10) || 0);
    const like = "%" + q.replace(/[\\%_]/g, "\\$&") + "%";
    const where = `(?1='' OR email LIKE ?2 ESCAPE '\\' OR name LIKE ?2 ESCAPE '\\' OR id=?1)
      AND (?3='' OR (?3='active' AND status='active') OR (?3='banned' AND status='banned') OR (?3='unverified' AND email_verified=0))`;
    const rows = await env.DB.prepare(`SELECT id,name,email,email_verified,points,status,created_at,last_login_at FROM users WHERE ${where} ORDER BY created_at DESC LIMIT 50 OFFSET ?4`).bind(q, like, status, offset).all();
    const total = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE ${where}`).bind(q, like, status).first()).n;
    return json({ ok: true, total, offset, users: rows.results.map(userOut) });
  }

  const um = /^\/admin\/api\/users\/([\w-]{1,64})(?:\/(\w[\w-]*))?$/.exec(path);
  if (um) {
    const [, uid, act] = um;
    const user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(uid).first();
    if (!user) throw bad("ユーザーが見つかりません", 404);
    if (!act && m === "GET") {
      const [sessions, ledger, grants, apps, pend] = await Promise.all([
        env.DB.prepare("SELECT device,created_at,last_used_at FROM sessions WHERE user_id=? AND expires_at>? ORDER BY last_used_at DESC").bind(uid, Date.now()).all(),
        env.DB.prepare("SELECT l.delta,l.balance_after,l.reason,l.source,l.created_at,c.name AS app FROM point_ledger l LEFT JOIN oauth_clients c ON c.id=l.actor WHERE l.user_id=? ORDER BY l.created_at DESC, l.rowid DESC LIMIT 30").bind(uid).all(),
        env.DB.prepare("SELECT c.name,g.scopes,g.updated_at FROM oauth_grants g JOIN oauth_clients c ON c.id=g.client_id WHERE g.user_id=?").bind(uid).all(),
        env.DB.prepare("SELECT COUNT(*) AS n FROM oauth_clients WHERE owner_user_id=?").bind(uid).first(),
        env.DB.prepare("SELECT new_email FROM email_changes WHERE user_id=? AND expires_at>?").bind(uid, Date.now()).first(),
      ]);
      return json({
        ok: true, user: { ...userOut(user), banReason: user.ban_reason, bannedAt: user.banned_at, pendingEmail: pend ? pend.new_email : null, ownedApps: apps.n },
        sessions: sessions.results.map((x) => ({ device: x.device, createdAt: x.created_at, lastUsedAt: x.last_used_at })),
        ledger: ledger.results.map((x) => ({ delta: x.delta, balanceAfter: x.balance_after, reason: x.reason, source: x.source === "admin" ? "運営" : x.app || "外部アプリ", createdAt: x.created_at })),
        grants: grants.results.map((x) => ({ app: x.name, scopes: x.scopes, updatedAt: x.updated_at })),
      });
    }
    if (m !== "POST") throw bad("Method not allowed", 405);
    if (act === "points") {
      const { amount, reason } = pointArgs(await readJson(req));
      const balance = await adjustOne(env, uid, amount, reason);
      await audit(env, req, "points.adjust", user.email, { amount, reason, balance });
      return json({ ok: true, points: balance, message: `${amount > 0 ? "+" : ""}${amount} pt(残高 ${balance})` });
    }
    if (act === "ban") {
      const reason = cleanText((await readJson(req)).reason, 200);
      if (!reason) throw bad("BANの理由を入力してください");
      await env.DB.prepare("UPDATE users SET status='banned', ban_reason=?, banned_at=? WHERE id=?").bind(reason, Date.now(), uid).run();
      await revokeAccess(env, uid); // セッション・OAuthトークンを即時失効
      await audit(env, req, "user.ban", user.email, { reason });
      return json({ ok: true, message: "アカウントを停止し、全セッションを失効しました" });
    }
    if (act === "unban") {
      await env.DB.prepare("UPDATE users SET status='active', ban_reason=NULL, banned_at=NULL WHERE id=?").bind(uid).run();
      await audit(env, req, "user.unban", user.email);
      return json({ ok: true, message: "停止を解除しました" });
    }
    if (act === "revoke-sessions") {
      await revokeAccess(env, uid);
      await audit(env, req, "user.revoke_sessions", user.email);
      return json({ ok: true, message: "全端末をログアウトしました" });
    }
    if (act === "send-reset") {
      await sendPasswordReset(env, user);
      await audit(env, req, "user.send_reset", user.email);
      return json({ ok: true, message: "パスワード再設定メールを送信しました(1時間有効)" });
    }
    if (act === "delete") {
      await deleteUserFully(req, env, user);
      return json({ ok: true, message: "アカウントと関連データを完全に削除しました" });
    }
    if (act === "verify-email") {
      await env.DB.prepare("UPDATE users SET email_verified=1 WHERE id=?").bind(uid).run();
      await audit(env, req, "user.verify_email", user.email);
      return json({ ok: true, message: "メール確認済みにしました" });
    }
    throw bad("Not found", 404);
  }

  if (path === "/admin/api/points/distribute" && m === "POST") return distribute(req, env);

  // ----- OAuth アプリ(points:write はここからのみ付与できる) -----
  if (path === "/admin/api/apps" && m === "GET") {
    const rows = await env.DB.prepare("SELECT c.*, u.email AS owner_email FROM oauth_clients c LEFT JOIN users u ON u.id=c.owner_user_id ORDER BY c.created_at DESC").all();
    return json({ ok: true, apps: rows.results.map((c) => publicClient(c, { admin: true })) });
  }
  if (path === "/admin/api/apps" && m === "POST") {
    const b = await readJson(req);
    const limit = Number.isInteger(b.pointsDailyLimit) ? b.pointsDailyLimit : 10000;
    if (limit < 1 || limit > 100000000) throw bad("24時間上限が不正です");
    const created = await insertClient(env, { name: b.name, description: b.description, redirectUris: cleanRedirects(b.redirectUris), scopes: adminScopes(b.scopes), createdBy: "admin", dailyLimit: limit });
    await audit(env, req, "app.create", created.id, { name: b.name, scopes: b.scopes });
    return json({ ok: true, id: created.id, clientSecret: created.secret, message: "アプリを作成しました。シークレットはこの画面でしか表示されません" });
  }
  const am = /^\/admin\/api\/apps\/([\w-]{1,64})\/(update|rotate|delete)$/.exec(path);
  if (am && m === "POST") {
    const [, id, act] = am;
    const c = await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=?").bind(id).first();
    if (!c) throw bad("アプリが見つかりません", 404);
    if (act === "rotate") {
      const secret = await rotateSecret(env, id);
      await audit(env, req, "app.rotate_secret", id, { name: c.name });
      return json({ ok: true, clientSecret: secret, message: "シークレットを再発行しました" });
    }
    if (act === "delete") {
      await deleteClient(env, id);
      await audit(env, req, "app.delete", id, { name: c.name });
      return json({ ok: true, message: "アプリを削除しました" });
    }
    const b = await readJson(req);
    const limit = Number.isInteger(b.pointsDailyLimit) ? b.pointsDailyLimit : c.points_daily_limit;
    if (limit < 1 || limit > 100000000) throw bad("24時間上限が不正です");
    const status = b.status === "disabled" ? "disabled" : "active";
    const nm = cleanText(b.name, 60);
    if (!nm) throw bad("アプリ名を入力してください");
    const scopes = adminScopes(b.scopes);
    await env.DB.prepare("UPDATE oauth_clients SET name=?,description=?,redirect_uris=?,scopes=?,points_daily_limit=?,status=?,updated_at=? WHERE id=?")
      .bind(nm, cleanText(b.description, 200), JSON.stringify(cleanRedirects(b.redirectUris)), scopes, limit, status, Date.now(), id).run();
    if (status === "disabled") await env.DB.prepare("DELETE FROM oauth_tokens WHERE client_id=?").bind(id).run();
    await audit(env, req, "app.update", id, { name: nm, scopes, status, limit, was: c.scopes });
    return json({ ok: true, message: "アプリを更新しました" });
  }

  if (path === "/admin/api/audit" && m === "GET") {
    const offset = Math.max(0, parseInt(new URL(req.url).searchParams.get("offset") || "0", 10) || 0);
    const rows = await env.DB.prepare("SELECT ts,action,target,detail,ip FROM admin_audit ORDER BY id DESC LIMIT 100 OFFSET ?").bind(offset).all();
    return json({ ok: true, entries: rows.results });
  }

  if (path === "/admin/api/logout" && m === "POST") {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE id=?").bind(s.id).run();
    return json({ ok: true }, 200, { "Set-Cookie": setCookie(req, "", 0) });
  }
  return null;
}
const userOut = (u) => ({ id: u.id, name: u.name, email: u.email, emailVerified: !!u.email_verified, points: u.points, status: u.status, createdAt: u.created_at, lastLoginAt: u.last_login_at });

// proxy=true: GAS(Code.gs)からの中継。/v1/admin/* を /admin/api/* として扱い、Cookie の代わりに X-Admin-Token を使う。
// 画面(HTML)は返さない。呼び出し前に index.js で APP_KEY を検証済み。
export async function handleAdmin(req, env, path, proxy = false) {
  if (!adminEnabled(env)) return new Response("Not found", { status: 404 });

  if (!proxy && path === "/admin") {
    if (req.method !== "GET") return new Response("Method not allowed", { status: 405 });
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    return new Response(adminHtml(nonce), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
        "X-Robots-Tag": "noindex, nofollow",
        ...SECURITY_HEADERS,
      },
    });
  }
  if (!path.startsWith("/admin/api/")) return new Response("Not found", { status: 404 });

  if (path === "/admin/api/login" && req.method === "POST") {
    const o = req.headers.get("Origin");
    if (o && o !== new URL(req.url).origin) throw bad("Forbidden", 403);
    return login(req, env, proxy);
  }
  const s = await currentSession(req, env, proxy);
  if (path === "/admin/api/session" && req.method === "GET") {
    return s ? json({ ok: true, csrf: s.csrf }) : json({ ok: false }, 401);
  }
  if (!s) throw bad("ログインが必要です", 401);
  if (req.method !== "GET") {
    const o = req.headers.get("Origin");
    if (o && o !== new URL(req.url).origin) throw bad("Forbidden", 403);
    if (!(await safeEqual(req.headers.get("X-CSRF-Token") || "", s.csrf))) throw bad("CSRFトークンが不正です。ページを再読み込みしてください", 403);
  }
  const res = await route(req, env, path, s);
  if (!res) throw bad("Not found", 404);
  return res;
}
