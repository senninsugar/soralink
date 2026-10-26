// OAuthクライアント(外部アプリ)の登録・更新ロジック。開発者(GAS画面)と管理者(/admin)で共用。
//
// ポイントを管理できるスコープ(points:write)は ADMIN_ONLY_SCOPES。
// 開発者経由では DEV_SCOPES の範囲しか付与できず、points:write は管理者パネルからのみ付与できます。
import { HttpError, SCOPES, DEV_SCOPES, ADMIN_ONLY_SCOPES, parseScopes, randomToken, sha256, uuid, cleanText } from "./util.js";

function validRedirect(u) {
  let url;
  try { url = new URL(u); } catch { return false; }
  if (url.hash || url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}
export function cleanRedirects(input) {
  const list = Array.isArray(input) ? input : String(input || "").split(/\r?\n/);
  const out = [...new Set(list.map((s) => String(s).trim()).filter(Boolean))];
  if (!out.length) throw new HttpError(400, "リダイレクトURIを1つ以上指定してください");
  if (out.length > 5) throw new HttpError(400, "リダイレクトURIは5件までです");
  for (const u of out) {
    if (u.length > 300 || !validRedirect(u)) throw new HttpError(400, `リダイレクトURIが不正です(httpsのみ。http は localhost / 127.0.0.1 のみ): ${u.slice(0, 60)}`);
  }
  return out;
}

// 開発者が選べるスコープ。管理者承認済みスコープ(既存のもの)は保持する
export function devScopes(requested, existing = "") {
  const asked = parseScopes(Array.isArray(requested) ? requested.join(" ") : requested);
  const held = parseScopes(existing);
  const adminOnly = asked.filter((s) => ADMIN_ONLY_SCOPES.includes(s) && !held.includes(s));
  if (adminOnly.length) throw new HttpError(403, `${adminOnly.join(", ")} は管理者のみが付与できる権限です。開発者設定からは選べません`);
  const unknown = asked.filter((s) => !(s in SCOPES));
  if (unknown.length) throw new HttpError(400, "不明なスコープです: " + unknown.join(", "));
  const picked = asked.filter((s) => DEV_SCOPES.includes(s));
  if (!picked.length) throw new HttpError(400, "スコープを1つ以上選んでください");
  const kept = held.filter((s) => ADMIN_ONLY_SCOPES.includes(s)); // 管理者が付与済みの権限は開発者の編集で消えない
  return [...picked, ...kept].join(" ");
}
export function adminScopes(requested) {
  const picked = parseScopes(Array.isArray(requested) ? requested.join(" ") : requested).filter((s) => s in SCOPES);
  if (!picked.length) throw new HttpError(400, "スコープを1つ以上選んでください");
  return picked.join(" ");
}

export async function newCredentials() {
  const id = "sa_" + randomToken(16);
  const secret = "sas_" + randomToken(32);
  return { id, secret, secretHash: await sha256(secret) };
}

export async function insertClient(env, { name, description, redirectUris, scopes, ownerId = null, createdBy, dailyLimit = 10000 }) {
  const nm = cleanText(name, 60);
  if (!nm) throw new HttpError(400, "アプリ名を入力してください");
  const cred = await newCredentials();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO oauth_clients(id,secret_hash,name,description,owner_user_id,redirect_uris,scopes,points_daily_limit,status,created_by,created_at,updated_at)
     VALUES(?,?,?,?,?,?,?,?,'active',?,?,?)`
  ).bind(cred.id, cred.secretHash, nm, cleanText(description, 200), ownerId, JSON.stringify(redirectUris), scopes, dailyLimit, createdBy, now, now).run();
  return { id: cred.id, secret: cred.secret };
}

export async function rotateSecret(env, clientId) {
  const secret = "sas_" + randomToken(32);
  await env.DB.prepare("UPDATE oauth_clients SET secret_hash=?, updated_at=? WHERE id=?").bind(await sha256(secret), Date.now(), clientId).run();
  return secret;
}

export function publicClient(c, { admin = false } = {}) {
  const base = {
    id: c.id, name: c.name, description: c.description,
    redirectUris: JSON.parse(c.redirect_uris), scopes: parseScopes(c.scopes),
    status: c.status, createdBy: c.created_by, createdAt: c.created_at,
    pointsApproved: parseScopes(c.scopes).includes("points:write"),
  };
  if (admin) Object.assign(base, { ownerUserId: c.owner_user_id, ownerEmail: c.owner_email || null, pointsDailyLimit: c.points_daily_limit });
  return base;
}

export async function deleteClient(env, clientId) {
  await env.DB.prepare("DELETE FROM oauth_clients WHERE id=?").bind(clientId).run(); // codes/tokens/grants は CASCADE
}
export const newId = uuid;
