// ログインセッション: 不透明なランダムトークン(DBに保存されるのはハッシュのみ)。
// DBの行を消せば即座に失効します(JWTと違い、ログアウト/BAN/パスワード変更が確実に効く)。
import { randomToken, sha256, uuid, cleanText } from "./util.js";

// 14日間の固定セッション。有効期限はDB側で検証し、ブラウザを閉じても期限までは保持する。
export const SESSION_TTL_MS = 14 * 24 * 3600 * 1000;
const MAX_SESSIONS = 10;

export async function createSession(env, userId, device) {
  const token = "ses_" + randomToken(32);
  const id = uuid(), now = Date.now();
  await env.DB.batch([
    // 古いものから消して、常に最大 MAX_SESSIONS 件
    env.DB.prepare(
      "DELETE FROM sessions WHERE user_id=?1 AND id NOT IN (SELECT id FROM sessions WHERE user_id=?1 ORDER BY created_at DESC LIMIT ?2)"
    ).bind(userId, MAX_SESSIONS - 1),
    env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,device,created_at,last_used_at,expires_at) VALUES(?,?,?,?,?,?,?)")
      .bind(id, userId, await sha256(token), cleanText(device, 100) || "不明な端末", now, now, now + SESSION_TTL_MS),
  ]);
  return { token, id };
}

export function bearer(req) {
  const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get("Authorization") || "");
  return m ? m[1] : "";
}

// -> { user, sid } | null   (期限切れ・BAN済みは null)
export async function authSession(req, env) {
  const token = bearer(req);
  if (!token.startsWith("ses_") || token.length > 100) return null;
  const row = await env.DB.prepare(
    `SELECT s.id AS sid, s.created_at AS session_created_at, s.expires_at, s.last_used_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`
  ).bind(await sha256(token)).first();
  if (!row || row.expires_at <= Date.now() || row.status !== "active") return null;
  const now = Date.now();
  // 有効な旧7日セッションは、作成時刻から14日まで延長(期限切れを復活させない)。
  const intendedExpiry = row.session_created_at + SESSION_TTL_MS;
  if (row.expires_at < intendedExpiry) {
    await env.DB.prepare("UPDATE sessions SET expires_at=? WHERE id=? AND expires_at>? ").bind(intendedExpiry, row.sid, now).run();
  }
  if (now - row.last_used_at > 10 * 60 * 1000) {
    await env.DB.prepare("UPDATE sessions SET last_used_at=? WHERE id=?").bind(now, row.sid).run();
  }
  const { sid, session_created_at, expires_at, last_used_at, ...user } = row;
  return { user, sid };
}

// ユーザーの全セッション(と、必要ならOAuthトークン)を失効。keepSid を渡すとそのセッションだけ残す
export async function revokeAccess(env, userId, { keepSid = null, oauth = true } = {}) {
  const stmts = [
    keepSid
      ? env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND id<>?").bind(userId, keepSid)
      : env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(userId),
  ];
  if (oauth) {
    stmts.push(env.DB.prepare("DELETE FROM oauth_tokens WHERE user_id=?").bind(userId));
    stmts.push(env.DB.prepare("DELETE FROM oauth_codes WHERE user_id=?").bind(userId));
  }
  await env.DB.batch(stmts);
}

export function publicUser(u, extra = {}) {
  return {
    id: u.id, name: u.name, email: u.email, points: u.points || 0,
    emailVerified: !!u.email_verified, createdAt: u.created_at, ...extra,
  };
}
