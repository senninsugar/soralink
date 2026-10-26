// Workerが直接返すHTMLページ(メール確認 / メール変更確認 / OAuth同意画面)
import { esc, SCOPES } from "./util.js";

export const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
};

export const CSS = `
:root{--blue:#1a73e8;--blue-h:#1557b0;--border:#dadce0;--text:#202124;--sub:#5f6368;--red:#d93025}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Roboto,"Noto Sans JP",-apple-system,"Segoe UI",Arial,sans-serif;color:var(--text);background:#fff;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:16px}
.card{width:100%;max-width:480px;border:1px solid var(--border);border-radius:8px;padding:36px}
.brand{text-align:center;font-size:22px;margin-bottom:20px}.brand b{color:var(--blue);font-weight:500}
h1{font-size:22px;font-weight:400;text-align:center;margin-bottom:8px}
.sub{text-align:center;color:var(--sub);font-size:14px;margin-bottom:22px;line-height:1.6}
input[type=email],input[type=password]{width:100%;padding:12px 14px;font-size:15px;border:1px solid var(--border);border-radius:4px;margin-bottom:12px}
input:focus{outline:2px solid var(--blue);border-color:transparent}
button{width:100%;height:40px;font-size:14px;font-weight:500;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:#fff;color:var(--blue);margin-top:8px}
button.primary{background:var(--blue);color:#fff;border-color:var(--blue)}button.primary:hover{background:var(--blue-h)}
.box{background:#f8f9fa;border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:18px;font-size:14px}
.box b{display:block;margin-bottom:4px}
.scopes{list-style:none;font-size:13px;color:var(--sub)}.scopes li{padding-left:20px;position:relative;margin:6px 0}
.scopes li:before{content:"✓";color:#137333;position:absolute;left:0;font-weight:700}
.scopes li.warn{color:#b3261e}.scopes li.warn:before{content:"!";color:#b3261e}
.err{background:#fce8e6;color:#b3261e;border-radius:4px;padding:10px 12px;font-size:13px;margin-bottom:14px}
.ok{color:#137333}.small{font-size:12px;color:var(--sub);margin-top:16px;line-height:1.6;text-align:center}
`;

export function htmlResponse(body, { status = 200, csp, extra = {} } = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": csp || "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      ...SECURITY_HEADERS,
      ...extra,
    },
  });
}

const doc = (title, inner) => `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head><body><div class="card"><div class="brand">Sennin<b>Account</b></div>${inner}</div></body></html>`;

export function messagePage(title, message, { status = 200, ok = false } = {}) {
  return htmlResponse(doc(title, `<h1 class="${ok ? "ok" : ""}">${esc(title)}</h1><p class="sub">${esc(message)}</p>`), { status });
}

// 確認ボタン付き中間ページ(メールのリンクをメーラーやセキュリティスキャナが先読みしても消費されないようにする)
export function confirmPage({ title, message, action, token, button }) {
  return htmlResponse(doc(title, `<h1>${esc(title)}</h1><p class="sub">${esc(message)}</p>
<form method="POST" action="${esc(action)}"><input type="hidden" name="token" value="${esc(token)}"><button class="primary" type="submit">${esc(button)}</button></form>`));
}

// OAuth 同意(+ログイン)ページ。CSP の form-action は意図的に付けない
// (認可後に外部の redirect_uri へ 303 で飛ばすため。Chromeは form-action をリダイレクト先にも適用する)
export function authorizePage({ client, scopes, params, error, email = "" }) {
  const hidden = ["client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"]
    .map((k) => (params[k] != null ? `<input type="hidden" name="${k}" value="${esc(params[k])}">` : ""))
    .join("");
  const lis = scopes.map((s) => `<li class="${s === "points:write" ? "warn" : ""}">${esc(SCOPES[s] || s)}</li>`).join("");
  const by = client.created_by === "admin" ? "運営が登録したアプリ" : "開発者が登録したアプリ";
  return htmlResponse(
    doc("アクセス権の確認", `<h1>アクセス権の確認</h1><p class="sub">外部アプリがあなたのアカウントへのアクセスを求めています</p>
<div class="box"><b>${esc(client.name)}</b>${esc(client.description || "")}<div style="color:#5f6368;font-size:12px;margin-top:6px">${by}</div></div>
<div class="box"><b>このアプリは以下にアクセスできます:</b><ul class="scopes">${lis}</ul></div>
${error ? `<div class="err">${esc(error)}</div>` : ""}
<form method="POST" autocomplete="on">${hidden}
<input type="email" name="email" placeholder="メールアドレス" value="${esc(email)}" required autocomplete="username">
<input type="password" name="password" placeholder="パスワード" required autocomplete="current-password">
<button class="primary" type="submit" name="decision" value="allow">許可する</button>
<button type="submit" name="decision" value="deny" formnovalidate>キャンセル</button></form>
<p class="small">このページのURLが Sennin Account のものであることを確認してください。<br>許可は連携アプリ画面からいつでも取り消せます。</p>`),
    { csp: "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" }
  );
}
