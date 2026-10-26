// Resend によるメール送信
import { esc } from "./util.js";

export async function sendMail(env, to, subject, html, text) {
  // 開発用: DEV_MAIL_LOG=1 のとき実送信せずログに出す(本番では設定しないこと)
  if (env.DEV_MAIL_LOG === "1") {
    console.log("MAIL_LOG " + JSON.stringify({ to, subject, text }));
    return;
  }
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) throw new Error("RESEND_API_KEY / MAIL_FROM is not configured");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, html, text }),
  });
  if (!r.ok) {
    console.error("resend failed", r.status, (await r.text()).slice(0, 300));
    throw new Error("mail send failed");
  }
}

function layout(title, paragraphs, button) {
  const ps = paragraphs.map((p) => `<p style="margin:0 0 14px;line-height:1.7">${p}</p>`).join("");
  const btn = button
    ? `<p style="margin:22px 0"><a href="${esc(button.href)}" style="background:#1a73e8;color:#fff;text-decoration:none;padding:11px 22px;border-radius:4px;font-weight:600;display:inline-block">${esc(button.label)}</a></p>
       <p style="font-size:12px;color:#5f6368;word-break:break-all">ボタンが開けない場合は次のURLをブラウザに貼り付けてください:<br>${esc(button.href)}</p>`
    : "";
  return `<!doctype html><html lang="ja"><body style="margin:0;background:#f6f8fc;padding:24px;font-family:-apple-system,'Segoe UI','Noto Sans JP',sans-serif;color:#202124">
  <div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #dadce0;border-radius:8px;padding:32px">
  <div style="font-size:20px;margin-bottom:18px">Sennin<b style="color:#1a73e8">Account</b></div>
  <h1 style="font-size:18px;font-weight:600;margin:0 0 16px">${esc(title)}</h1>${ps}${btn}
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0 12px"><p style="font-size:12px;color:#5f6368;margin:0">このメールに心当たりがない場合は、何もせずに破棄してください。</p></div></body></html>`;
}

// mail(env,to,subject,{title,lines:[...],button:{label,href}})
export async function mail(env, to, subject, { title, lines, button }) {
  const html = layout(title, lines.map(esc), button);
  const text = [title, "", ...lines, ...(button ? ["", button.label + ": " + button.href] : [])].join("\n");
  await sendMail(env, to, subject, html, text);
}
export const baseUrl = (env) => String(env.API_BASE_URL || "").replace(/\/+$/, "");
