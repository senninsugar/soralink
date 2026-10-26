// Sennin Account API — エントリポイント / ルーティング
import { HttpError, json, safeEqual } from "./util.js";
import { handleV1, handleMailLinks } from "./users.js";
import { handleOAuth, handleApi } from "./oauth.js";
import { handleAdmin } from "./admin.js";
import { oauthTestHtml } from "./oauth_test_ui.js";
import { API_DOCS_TEMPLATE } from "./api_docs.js";
import { SECURITY_HEADERS } from "./pages.js";

// ブラウザから直接叩かれる外部アプリ向けエンドポイントだけ CORS を許可(Bearer/クライアント認証でCookieは使わない)
const CORS_PATHS = (p) => p === "/oauth/token" || p === "/oauth/revoke" || p === "/oauth/userinfo" || p.startsWith("/api/v1/") || p === "/.well-known/oauth-authorization-server" || p === "/llms.txt";
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "600",
};

function checkConfig(env) {
  const missing = [];
  if (!env.DB) missing.push("DB");
  if (!env.PASSWORD_PEPPER || env.PASSWORD_PEPPER.length < 32) missing.push("PASSWORD_PEPPER(32文字以上)");
  if (!env.APP_KEY || env.APP_KEY.length < 24) missing.push("APP_KEY(24文字以上)");
  if (!env.API_BASE_URL || /REPLACE_WITH/.test(env.API_BASE_URL)) missing.push("API_BASE_URL");
  return missing;
}

async function handle(req, env, ctx) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (path === "/health") return json({ ok: true, service: "sennin-account-api", version: 2 });

  if (path.startsWith("/admin")) return handleAdmin(req, env, path);

  // 仕様書(AIに読ませる用)。Markdown。リクエストされたURLのオリジンを埋め込んで返す
  if (path === "/llms.txt" || path === "/api-docs") {
    if (req.method !== "GET") throw new HttpError(405, "Method not allowed");
    return new Response(API_DOCS_TEMPLATE.replaceAll("{{BASE}}", url.origin), {
      headers: { "Content-Type": "text/markdown; charset=utf-8", "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" },
    });
  }

  // OAuth 動作確認ページ(Worker自身が配信するのでリダイレクトURIは <WorkerのURL>/oauth-test)
  if (path === "/oauth-test") {
    if (req.method !== "GET") throw new HttpError(405, "Method not allowed");
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    return new Response(oauthTestHtml(nonce), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
        "X-Robots-Tag": "noindex, nofollow",
        ...SECURITY_HEADERS,
      },
    });
  }

  if (path === "/verify" || path === "/confirm-email") {
    if (req.method !== "GET" && req.method !== "POST") throw new HttpError(405, "Method not allowed");
    return handleMailLinks(req, env, ctx, path);
  }

  if (path.startsWith("/oauth/") || path === "/.well-known/oauth-authorization-server") {
    const r = await handleOAuth(req, env, path);
    if (r) return r;
  }
  if (path.startsWith("/api/v1/")) return handleApi(req, env, path);

  if (path.startsWith("/v1/")) {
    // GAS(Code.gs) からのサーバー間呼び出し専用。共有キー無しは拒否(fail closed)
    if (!(await safeEqual(req.headers.get("X-App-Key") || "", env.APP_KEY))) throw new HttpError(403, "Forbidden");
    // GAS の管理者画面からの中継: /v1/admin/* -> 管理者API(/admin/api/*)。認証は X-Admin-Token
    if (path.startsWith("/v1/admin/")) return handleAdmin(req, env, "/admin/api" + path.slice("/v1/admin".length), true);
    return handleV1(req, env, ctx, path);
  }
  return json({ ok: false, error: "Not found" }, 404);
}

export default {
  async fetch(req, env, ctx) {
    const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
    const cors = CORS_PATHS(path);
    if (req.method === "OPTIONS") return cors ? new Response(null, { status: 204, headers: CORS }) : new Response(null, { status: 404 });
    let res;
    try {
      const missing = checkConfig(env);
      if (missing.length && path !== "/health") {
        console.error("config missing: " + missing.join(", "));
        throw new HttpError(500, "サーバー設定が未完了です");
      }
      res = await handle(req, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) {
        const headers = e.extra && e.extra.retryAfter ? { "Retry-After": String(e.extra.retryAfter) } : {};
        res = json({ ok: false, error: e.message, ...(e.extra && e.extra.retryAfter ? { retryAfter: e.extra.retryAfter } : {}) }, e.status, headers);
      } else {
        console.error("unhandled", e && e.stack || e); // 詳細はログにのみ出す(クライアントには返さない)
        res = json({ ok: false, error: "サーバーエラーが発生しました" }, 500);
      }
    }
    if (cors) { res = new Response(res.body, res); for (const [k, v] of Object.entries(CORS)) res.headers.set(k, v); }
    return res;
  },

  // 期限切れデータの掃除(cron)
  async scheduled(event, env, ctx) {
    const now = Date.now();
    ctx.waitUntil(env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM email_tokens WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM email_changes WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM email_codes WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM oauth_codes WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM oauth_tokens WHERE refresh_expires < ?").bind(now),
      env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at < ?").bind(now),
      env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 2 * 86400000),
      env.DB.prepare("DELETE FROM users WHERE email_verified=0 AND created_at < ?").bind(now - 7 * 86400000), // 7日以上未確認の仮登録
      env.DB.prepare("DELETE FROM admin_audit WHERE ts < ?").bind(now - 180 * 86400000),
    ]));
  },
};
