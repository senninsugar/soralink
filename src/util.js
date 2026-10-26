// 共通ユーティリティ: 暗号 / レスポンス / 入力検証 / レート制限 / 監査ログ

export const enc = new TextEncoder();

export class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

// ---------- encoding / crypto ----------
export function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
export function unb64url(s) {
  const b = atob(String(s).replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (String(s).length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
export const randomToken = (bytes = 32) => b64url(crypto.getRandomValues(new Uint8Array(bytes)));
export const uuid = () => crypto.randomUUID();
export async function sha256(str) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(String(str))));
}
// 定数時間比較(ダイジェスト同士を比較するので長さも漏れない)
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([sha256(a), sha256(b)]);
  let d = x.length ^ y.length;
  for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return d === 0;
}

// ---------- password hashing ----------
// Cloudflare Workers の制約:
//   * WebCrypto の PBKDF2 は反復回数 100,000 回まで
//   * 無料プランは 1 リクエストあたり CPU 10ms まで(実測: SHA-512 で 100,000 回≒60ms, 4,000 回≒2.7ms)
// そのため反復回数は環境変数 PBKDF2_ITERATIONS で設定します(既定 4000 = 無料プラン向け)。
// 反復回数はハッシュ文字列に埋め込まれ、有料プランへ移行して値を上げると、各ユーザーの次回ログイン時に自動で再ハッシュされます。
// 反復回数の弱さは、サーバー秘密(PASSWORD_PEPPER)でHMACしてから導出すること、厳しいログイン失敗ロック、12文字以上の必須化で補います。
const DEFAULT_ITER = 4000, MAX_ITER = 100000;
export function targetIterations(env) {
  const n = parseInt(env.PBKDF2_ITERATIONS, 10);
  return Number.isFinite(n) ? Math.min(MAX_ITER, Math.max(1000, n)) : DEFAULT_ITER;
}
async function derive(env, password, salt, iter) {
  if (!env.PASSWORD_PEPPER || env.PASSWORD_PEPPER.length < 32) throw new Error("PASSWORD_PEPPER is not configured");
  const hk = await crypto.subtle.importKey("raw", enc.encode(env.PASSWORD_PEPPER), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const peppered = await crypto.subtle.sign("HMAC", hk, enc.encode(password));
  const pk = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-512" }, pk, 256));
}
export async function hashPassword(env, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iter = targetIterations(env);
  const h = await derive(env, password, salt, iter);
  return `v1$${iter}$${b64url(salt)}$${b64url(h)}`;
}
export async function verifyPassword(env, password, stored) {
  const p = String(stored || "").split("$");
  if (p.length !== 4 || p[0] !== "v1") return false;
  const iter = Math.min(parseInt(p[1], 10) || DEFAULT_ITER, MAX_ITER);
  const h = await derive(env, password, unb64url(p[2]), iter);
  return safeEqual(b64url(h), p[3]);
}
// 保存済みハッシュの反復回数が現在の設定より低ければ true(ログイン成功時に再ハッシュする)
export function needsRehash(env, stored) {
  const p = String(stored || "").split("$");
  return p.length === 4 && (parseInt(p[1], 10) || 0) < targetIterations(env);
}

const COMMON_PASSWORDS = new Set([
  "password1234", "123456789012", "qwertyuiop12", "passwordpassword", "administrator", "1234567890123",
  "111111111111", "000000000000", "abcdefghijkl", "iloveyou1234", "senninaccount",
]);
export function passwordProblem(password, email = "") {
  if (typeof password !== "string") return "パスワードが不正です";
  if (password.length < 12 || password.length > 128) return "パスワードは12〜128文字にしてください";
  const low = password.toLowerCase();
  if (email && low === String(email).toLowerCase()) return "パスワードにメールアドレスは使用できません";
  if (COMMON_PASSWORDS.has(low) || /^(.)\1+$/.test(password)) return "推測されやすいパスワードです。別のものにしてください";
  return null;
}

// ---------- http ----------
export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}
export const clientIp = (req) => req.headers.get("CF-Connecting-IP") || "unknown";

export async function readText(req, max = 32768) {
  const len = parseInt(req.headers.get("Content-Length") || "0", 10);
  if (len > max) throw new HttpError(413, "リクエストが大きすぎます");
  const text = await req.text();
  if (text.length > max) throw new HttpError(413, "リクエストが大きすぎます");
  return text;
}
export async function readJson(req) {
  const text = await readText(req);
  if (!text) return {};
  try {
    const v = JSON.parse(text);
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v;
  } catch {
    throw new HttpError(400, "リクエスト形式が不正です");
  }
}
// OAuth トークンエンドポイント用: form または JSON
export async function readParams(req) {
  const text = await readText(req);
  const ct = (req.headers.get("Content-Type") || "").toLowerCase();
  if (ct.includes("application/json")) {
    try { return JSON.parse(text) || {}; } catch { throw new HttpError(400, "invalid_request"); }
  }
  return Object.fromEntries(new URLSearchParams(text));
}

// ---------- validation ----------
export function normEmail(v) {
  const e = String(v || "").trim().toLowerCase();
  if (e.length > 254) return null;
  return /^[^\s@<>"',;()\\]+@[^\s@<>"',;()\\]+\.[^\s@<>"',;()\\]+$/.test(e) ? e : null;
}
export function cleanText(v, max) {
  return String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}
export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------- rate limiting (D1, fixed window) ----------
// 注意: GAS(UrlFetchApp)経由のリクエストは Google のIPから来るため、/v1/* は「IP」ではなく
// 「メールアドレス/ユーザーID/エンドポイント全体」でキーを切っています。直接アクセスされる
// /oauth/* と /admin はクライアントIP(CF-Connecting-IP)で制限します。
export async function hit(env, bucket, id, max, windowSec) {
  const key = bucket + ":" + (await sha256(String(id))).slice(0, 24);
  const now = Date.now(), win = windowSec * 1000;
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits(key,window_start,count) VALUES(?1,?2,1)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN window_start <= ?3 THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start END
     RETURNING count, window_start`
  ).bind(key, now, now - win).first();
  if (row.count > max) return { retryAfter: Math.max(1, Math.ceil((row.window_start + win - now) / 1000)) };
  return null;
}
// カウントを増やさずに現在の状態だけ確認する(失敗時だけ数えたいロックアウト用)
export async function peek(env, bucket, id, max, windowSec) {
  const key = bucket + ":" + (await sha256(String(id))).slice(0, 24);
  const now = Date.now(), win = windowSec * 1000;
  const row = await env.DB.prepare("SELECT count, window_start FROM rate_limits WHERE key=?").bind(key).first();
  if (row && row.window_start > now - win && row.count >= max) return { retryAfter: Math.max(1, Math.ceil((row.window_start + win - now) / 1000)) };
  return null;
}
// specs: [bucket, id, max, windowSec][] -> 最初に超過したものを返す
export async function limited(env, specs) {
  for (const [bucket, id, max, win] of specs) {
    const r = await hit(env, bucket, id, max, win);
    if (r) return r;
  }
  return null;
}
export const tooMany = (r) =>
  new HttpError(429, `リクエストが多すぎます。${r.retryAfter >= 90 ? Math.ceil(r.retryAfter / 60) + "分" : r.retryAfter + "秒"}ほど待ってから再試行してください`, { retryAfter: r.retryAfter });

// ---------- audit ----------
export async function audit(env, req, action, target, detail) {
  await env.DB.prepare("INSERT INTO admin_audit(ts,action,target,detail,ip) VALUES(?,?,?,?,?)")
    .bind(Date.now(), action, target || null, detail ? JSON.stringify(detail).slice(0, 1000) : null, req ? clientIp(req) : null).run();
}

export const SCOPES = {
  profile: "名前・ユーザーIDの参照",
  email: "メールアドレスの参照",
  "points:read": "ポイント残高の参照",
  "points:write": "ポイントの加算・減算（管理者承認済みアプリのみ）",
};
export const DEV_SCOPES = ["profile", "email", "points:read"]; // 開発者が自分で選べるもの
export const ADMIN_ONLY_SCOPES = ["points:write"];            // 管理者だけが付与できる
export const parseScopes = (s) => [...new Set(String(s || "").split(/\s+/).filter(Boolean))];
export const hasScope = (granted, scope) => parseScopes(granted).includes(scope);
