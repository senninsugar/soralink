// GAS画面から呼ばれるユーザーAPI (/v1/*) と、メール内リンク用の公開ページ (/verify, /confirm-email)
import {
  HttpError, json, readJson, readText, normEmail, cleanText, passwordProblem, hashPassword, verifyPassword, needsRehash,
  randomToken, sha256, uuid, limited, peek, hit, tooMany, clientIp, parseScopes,
} from "./util.js";
import { mail, baseUrl } from "./mail.js";
import { createSession, authSession, revokeAccess, publicUser } from "./session.js";
import { messagePage, confirmPage } from "./pages.js";
import { cleanRedirects, devScopes, insertClient, rotateSecret, publicClient, deleteClient } from "./apps.js";

const DAY = 86400000;
const bad = (msg, status = 400) => new HttpError(status, msg);

async function issueToken(env, userId, purpose, ttlMs) {
  const token = randomToken(32);
  await env.DB.prepare(
    "INSERT INTO email_tokens(id,token_hash,purpose,expires_at) VALUES(?1,?2,?3,?4) ON CONFLICT(id,purpose) DO UPDATE SET token_hash=?2, expires_at=?4"
  ).bind(userId, await sha256(token), purpose, Date.now() + ttlMs).run();
  return token;
}
async function consumeToken(env, token, purpose) {
  if (!token || token.length > 100) return null;
  return env.DB.prepare("DELETE FROM email_tokens WHERE token_hash=? AND purpose=? AND expires_at>? RETURNING id")
    .bind(await sha256(token), purpose, Date.now()).first();
}
async function issueEmailCode(env, email, purpose = "verify") {
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO email_codes(email,purpose,code_hash,expires_at,attempts,last_sent_at)
     VALUES(?,?,?,?,0,?) ON CONFLICT(email,purpose) DO UPDATE SET
     code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0, last_sent_at=excluded.last_sent_at`
  ).bind(email, purpose, await sha256(code), now + 10 * 60 * 1000, now).run();
  return code;
}
async function sendVerificationCode(env, user) {
  const code = await issueEmailCode(env, user.email, "verify");
  await mail(env, user.email, "【Sennin Account】メール認証コード", {
    title: "メールアドレスの確認コード",
    lines: [`${user.name} さん`, "次の6桁のコードを Sennin Account の認証画面に入力してください。", `認証コード: ${code}`, "このコードは10分間有効です。心当たりがない場合は破棄してください。"],
  });
}
const notice = (env, to, subject, title, lines) => mail(env, to, "【Sennin Account】" + subject, { title, lines });

// ---------------- 公開: 登録 / ログイン / 再設定 ----------------
async function register(req, env, ctx) {
  const b = await readJson(req);
  const name = cleanText(b.name, 80), email = normEmail(b.email);
  if (!name || !email) throw bad("名前またはメールアドレスを確認してください");
  const pw = passwordProblem(b.password, email);
  if (pw) throw bad(pw);
  const r = await limited(env, [["reg-all", "*", 300, 3600], ["reg-email", email, 3, 3600]]);
  if (r) throw tooMany(r);

  const hash = await hashPassword(env, b.password); // 既存/新規どちらでも同じ計算コスト
  const generic = { ok: true, message: "認証コードをメールで送信しました。10分以内に入力してください。", verificationRequired: true };
  const existing = await env.DB.prepare("SELECT id,name,email,email_verified FROM users WHERE email=?").bind(email).first();

  if (existing) {
    // アカウントの存在を応答から推測させない。メールでだけ本人に知らせる
    if (existing.email_verified) {
      ctx.waitUntil(notice(env, email, "すでに登録されています", "すでにアカウントがあります", [
        "このメールアドレスで Sennin Account の登録が試みられましたが、すでにアカウントが存在します。",
        "ご自身で登録しようとした場合は、ログイン画面の「パスワードをお忘れですか？」から再設定できます。",
      ]).catch((e) => console.error(e.message)));
    } else {
      // 未確認アカウントの再登録: 最新の登録内容で上書きし、旧リンクは無効化(事前乗っ取り対策)
      await env.DB.prepare("UPDATE users SET name=?, password_hash=? WHERE id=?").bind(name, hash, existing.id).run();
      ctx.waitUntil(sendVerificationCode(env, { ...existing, name }).catch((e) => console.error(e.message)));
    }
    return json(generic);
  }

  const id = uuid();
  await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,email_verified,points,status,created_at) VALUES(?,?,?,?,0,0,'active',?)")
    .bind(id, name, email, hash, Date.now()).run();
  try {
    await sendVerificationCode(env, { name, email });
  } catch (e) {
    console.error("verify mail failed:", e.message);
    await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
    throw bad("メールを送信できませんでした。時間をおいて再試行してください", 502);
  }
  return json(generic);
}

async function verifyEmailCode(req, env) {
  const b = await readJson(req);
  const email = normEmail(b.email);
  const code = String(b.code || "").trim();
  if (!email || !/^\d{6}$/.test(code)) throw bad("メールアドレスと6桁の認証コードを入力してください");
  const limitedResult = await limited(env, [["verify-code-ip", clientIp(req), 30, 900], ["verify-code-email", email, 10, 900]]);
  if (limitedResult) throw tooMany(limitedResult);
  const row = await env.DB.prepare("SELECT * FROM email_codes WHERE email=? AND purpose='verify'").bind(email).first();
  if (!row || row.expires_at <= Date.now() || row.attempts >= 5) throw bad("認証コードが無効か期限切れです。再登録して新しいコードを受け取ってください", 400);
  const valid = await safeCodeEqual(await sha256(code), row.code_hash);
  if (!valid) {
    await env.DB.prepare("UPDATE email_codes SET attempts=attempts+1 WHERE email=? AND purpose='verify'").bind(email).run();
    throw bad("認証コードが正しくありません", 400);
  }
  const user = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
  if (!user) throw bad("認証を完了できませんでした", 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET email_verified=1 WHERE id=?").bind(user.id),
    env.DB.prepare("DELETE FROM email_codes WHERE email=? AND purpose='verify'").bind(email),
    env.DB.prepare("DELETE FROM email_tokens WHERE id=? AND purpose='verify'").bind(user.id),
  ]);
  return json({ ok: true, message: "メールアドレスを確認しました。ログインできます。" });
}
async function safeCodeEqual(a, b) {
  // sha256 hex digest; use constant-time comparison helper from util
  const { safeEqual } = await import("./util.js");
  return safeEqual(a, b);
}

async function login(req, env) {
  const b = await readJson(req);
  const email = normEmail(b.email), password = String(b.password || "").slice(0, 200);
  const fail = () => bad("メールアドレスまたはパスワードが正しくありません", 401);
  if (!email || !password) throw fail();
  // 失敗だけを数える(成功ログインでロックされない)。上限に達したメールは15分間、正しいパスワードでも拒否
  const r = (await peek(env, "login-fail", email, 10, 900)) || (await limited(env, [["login-all", "*", 3000, 900]]));
  if (r) throw tooMany(r);

  const u = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  const ok = u ? await verifyPassword(env, password, u.password_hash) : (await hashPassword(env, password), false); // 存在有無でコストを揃える
  if (!ok) { await hit(env, "login-fail", email, 10, 900); throw fail(); }
  if (u.status === "banned") throw bad("このアカウントは利用停止されています", 403);
  if (!u.email_verified) throw bad("メールアドレスの確認が完了していません。メールの認証コードを入力してください", 403);

  if (needsRehash(env, u.password_hash)) { // PBKDF2_ITERATIONS を上げた場合、ログイン成功時に強いハッシュへ更新
    await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hashPassword(env, password), u.id).run();
  }
  const { token, id } = await createSession(env, u.id, b.device);
  await env.DB.prepare("UPDATE users SET last_login_at=? WHERE id=?").bind(Date.now(), u.id).run();
  return json({ ok: true, token, user: publicUser(u), sessionId: id });
}

async function forgot(req, env, ctx) {
  const b = await readJson(req);
  const email = normEmail(b.email);
  const generic = json({ ok: true, message: "該当するアカウントがある場合、再設定メールを送信しました" });
  if (!email) return generic;
  const r = await limited(env, [["forgot-all", "*", 200, 3600], ["forgot-email", email, 3, 3600]]);
  if (r) throw tooMany(r);
  const u = await env.DB.prepare("SELECT id,name,email FROM users WHERE email=?").bind(email).first();
  if (u) {
    const token = await issueToken(env, u.id, "reset", 3600000);
    const link = String(env.APP_RESET_URL) + (String(env.APP_RESET_URL).includes("?") ? "&" : "?") + "resetToken=" + encodeURIComponent(token);
    // 送信待ちの時間差で存在有無が分からないよう、バックグラウンドで送る
    ctx.waitUntil(mail(env, email, "【Sennin Account】パスワードの再設定", {
      title: "パスワードの再設定",
      lines: [`${u.name} さん`, "下のボタンから新しいパスワードを設定してください(1時間有効・1回のみ)。"],
      button: { label: "パスワードを再設定する", href: link },
    }).catch((e) => console.error(e.message)));
  }
  return generic;
}

// 管理者画面から: 対象ユーザーにパスワード再設定メールを送る(管理者はパスワードを知る必要がない)
export async function sendPasswordReset(env, user) {
  const token = await issueToken(env, user.id, "reset", 3600000);
  const link = String(env.APP_RESET_URL) + (String(env.APP_RESET_URL).includes("?") ? "&" : "?") + "resetToken=" + encodeURIComponent(token);
  await mail(env, user.email, "【Sennin Account】パスワードの再設定", {
    title: "パスワードの再設定",
    lines: [`${user.name} さん`, "運営からパスワードの再設定が依頼されました。下のボタンから新しいパスワードを設定してください(1時間有効・1回のみ)。", "心当たりがない場合は、このメールを破棄してください。"],
    button: { label: "パスワードを再設定する", href: link },
  });
}

async function reset(req, env, ctx) {
  const b = await readJson(req);
  const r = await limited(env, [["reset-all", "*", 300, 3600]]);
  if (r) throw tooMany(r);
  const token = String(b.token || "");
  const pre = await env.DB.prepare("SELECT u.id,u.email FROM email_tokens t JOIN users u ON u.id=t.id WHERE t.token_hash=? AND t.purpose='reset' AND t.expires_at>?")
    .bind(await sha256(token), Date.now()).first();
  if (!pre) throw bad("再設定リンクが無効、または期限切れです。もう一度メールをリクエストしてください");
  const pw = passwordProblem(b.password, pre.email);
  if (pw) throw bad(pw);
  const row = await consumeToken(env, token, "reset");
  if (!row) throw bad("再設定リンクが無効、または期限切れです。もう一度メールをリクエストしてください");
  const hash = await hashPassword(env, b.password);
  // メールで本人確認できたので email_verified も立てる。全セッション/OAuthトークンを失効
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET password_hash=?, email_verified=1 WHERE id=?").bind(hash, row.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(row.id),
    env.DB.prepare("DELETE FROM oauth_tokens WHERE user_id=?").bind(row.id),
    env.DB.prepare("DELETE FROM oauth_codes WHERE user_id=?").bind(row.id),
  ]);
  ctx.waitUntil(notice(env, pre.email, "パスワードが変更されました", "パスワードを変更しました", [
    "パスワードが再設定されました。すべての端末からログアウトされています。",
    "心当たりがない場合は、すぐにパスワード再設定を行い、サポートへ連絡してください。",
  ]).catch((e) => console.error(e.message)));
  return json({ ok: true, message: "パスワードを再設定しました。新しいパスワードでログインしてください" });
}

// ---------------- メールのリンク先(ブラウザで直接開く) ----------------
// GETは確認ボタン付きの中間ページだけ返し、POSTでトークンを消費する(リンクのプリフェッチ対策)
export async function handleMailLinks(req, env, ctx, path) {
  const ip = clientIp(req);
  const lim = await limited(env, [["link-ip", ip, 60, 600]]);
  if (lim) return messagePage("しばらくお待ちください", "アクセスが多すぎます。少し待ってからお試しください。", { status: 429 });

  if (path === "/verify") {
    if (req.method === "GET") {
      const t = new URL(req.url).searchParams.get("token") || "";
      if (!t) return messagePage("リンクが無効です", "確認リンクが正しくありません。", { status: 400 });
      return confirmPage({ title: "メールアドレスの確認", message: "下のボタンを押すと、メールアドレスの確認が完了します。", action: "/verify", token: t, button: "確認を完了する" });
    }
    const token = new URLSearchParams(await readText(req)).get("token") || "";
    const row = await consumeToken(env, token, "verify");
    if (!row) return messagePage("リンクが無効です", "確認リンクが無効、または期限切れです。もう一度登録をやり直してください。", { status: 400 });
    await env.DB.prepare("UPDATE users SET email_verified=1 WHERE id=?").bind(row.id).run();
    return messagePage("確認が完了しました", "メールアドレスを確認しました。アカウント画面に戻ってログインしてください。", { ok: true });
  }

  if (path === "/confirm-email") {
    if (req.method === "GET") {
      const t = new URL(req.url).searchParams.get("token") || "";
      if (!t) return messagePage("リンクが無効です", "確認リンクが正しくありません。", { status: 400 });
      return confirmPage({ title: "メールアドレスの変更", message: "下のボタンを押すと、アカウントのメールアドレスが変更されます。セキュリティのため、すべての端末がログアウトされます。", action: "/confirm-email", token: t, button: "変更を確定する" });
    }
    const token = new URLSearchParams(await readText(req)).get("token") || "";
    const h = await sha256(token);
    const row = token.length < 100 && await env.DB.prepare("SELECT c.user_id,c.new_email,u.email AS old_email FROM email_changes c JOIN users u ON u.id=c.user_id WHERE c.token_hash=? AND c.expires_at>?").bind(h, Date.now()).first();
    if (!row) return messagePage("リンクが無効です", "確認リンクが無効、または期限切れです。もう一度変更手続きをやり直してください。", { status: 400 });
    try {
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET email=?, email_verified=1 WHERE id=?").bind(row.new_email, row.user_id),
        env.DB.prepare("DELETE FROM email_changes WHERE user_id=?").bind(row.user_id),
        env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(row.user_id),
        env.DB.prepare("DELETE FROM oauth_tokens WHERE user_id=?").bind(row.user_id),
        env.DB.prepare("DELETE FROM oauth_codes WHERE user_id=?").bind(row.user_id),
      ]);
    } catch (e) {
      if (/UNIQUE/i.test(String(e.message))) return messagePage("変更できません", "このメールアドレスはすでに使用されています。", { status: 409 });
      throw e;
    }
    ctx.waitUntil(notice(env, row.old_email, "メールアドレスが変更されました", "メールアドレスを変更しました", [
      `アカウントのメールアドレスが ${row.new_email} に変更されました。`, "心当たりがない場合は、至急サポートへ連絡してください。",
    ]).catch((e) => console.error(e.message)));
    return messagePage("変更が完了しました", "メールアドレスを変更しました。新しいメールアドレスでログインしてください。", { ok: true });
  }
  return null;
}

// ---------------- 認証必須 ----------------
const appOut = (c) => publicClient(c);
async function ownedApp(env, userId, id) {
  const c = await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=? AND owner_user_id=?").bind(String(id || ""), userId).first();
  if (!c) throw bad("アプリが見つかりません", 404);
  return c;
}

async function authed(req, env, ctx, path, auth) {
  const { user, sid } = auth;
  const m = req.method;

  if (path === "/v1/me" && m === "GET") {
    const pend = await env.DB.prepare("SELECT new_email FROM email_changes WHERE user_id=? AND expires_at>?").bind(user.id, Date.now()).first();
    return json({ ok: true, user: publicUser(user, { pendingEmail: pend ? pend.new_email : null }), sessionId: sid });
  }

  if (path === "/v1/profile" && m === "POST") {
    const b = await readJson(req);
    const name = cleanText(b.name, 80);
    if (!name) throw bad("名前を入力してください");
    await env.DB.prepare("UPDATE users SET name=? WHERE id=?").bind(name, user.id).run();
    return json({ ok: true, user: publicUser({ ...user, name }), message: "プロフィールを更新しました" });
  }

  if (path === "/v1/email/change" && m === "POST") {
    const b = await readJson(req);
    const newEmail = normEmail(b.newEmail);
    if (!newEmail) throw bad("新しいメールアドレスが不正です");
    if (newEmail === user.email) throw bad("現在のメールアドレスと同じです");
    const r = (await peek(env, "pwfail", user.id, 10, 900)) || (await limited(env, [["emailchg", user.id, 3, 3600]]));
    if (r) throw tooMany(r);
    if (!(await verifyPassword(env, String(b.password || "").slice(0, 200), user.password_hash))) { await hit(env, "pwfail", user.id, 10, 900); throw bad("パスワードが正しくありません", 403); }

    const taken = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(newEmail).first();
    const generic = { ok: true, message: "新しいメールアドレス宛に確認メールを送信しました。リンクを開くと変更が完了します(1時間有効)" };
    if (!taken) {
      const token = randomToken(32);
      await env.DB.prepare(
        "INSERT INTO email_changes(user_id,new_email,token_hash,expires_at,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(user_id) DO UPDATE SET new_email=?2, token_hash=?3, expires_at=?4, created_at=?5"
      ).bind(user.id, newEmail, await sha256(token), Date.now() + 3600000, Date.now()).run();
      try {
        await mail(env, newEmail, "【Sennin Account】新しいメールアドレスの確認", {
          title: "メールアドレス変更の確認",
          lines: [`${user.name} さん`, "このアドレスを Sennin Account の新しいメールアドレスに設定するには、下のボタンを押してください(1時間有効)。"],
          button: { label: "このアドレスに変更する", href: baseUrl(env) + "/confirm-email?token=" + encodeURIComponent(token) },
        });
      } catch (e) {
        console.error("email change mail failed:", e.message);
        await env.DB.prepare("DELETE FROM email_changes WHERE user_id=?").bind(user.id).run();
        throw bad("メールを送信できませんでした。時間をおいて再試行してください", 502);
      }
    }
    // 現在のアドレスにも通知(乗っ取り検知用)
    ctx.waitUntil(notice(env, user.email, "メールアドレス変更のリクエスト", "メールアドレス変更がリクエストされました", [
      "アカウントのメールアドレスを別のアドレスへ変更する手続きが開始されました。",
      "ご自身の操作でない場合は、すぐにパスワードを変更してください。",
    ]).catch((e) => console.error(e.message)));
    return json(generic);
  }

  if (path === "/v1/password" && m === "POST") {
    const b = await readJson(req);
    const r = await peek(env, "pwfail", user.id, 10, 900);
    if (r) throw tooMany(r);
    if (!(await verifyPassword(env, String(b.currentPassword || "").slice(0, 200), user.password_hash))) { await hit(env, "pwfail", user.id, 10, 900); throw bad("現在のパスワードが正しくありません", 403); }
    const pw = passwordProblem(b.newPassword, user.email);
    if (pw) throw bad(pw);
    const hash = await hashPassword(env, b.newPassword);
    await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(hash, user.id).run();
    await revokeAccess(env, user.id, { keepSid: sid }); // 他の端末・連携アプリのトークンを失効。今の端末は維持
    ctx.waitUntil(notice(env, user.email, "パスワードが変更されました", "パスワードを変更しました", [
      "アカウントのパスワードが変更されました。他の端末はログアウトされています。", "心当たりがない場合は、至急パスワードを再設定してください。",
    ]).catch((e) => console.error(e.message)));
    return json({ ok: true, message: "パスワードを変更しました。他の端末はログアウトされました" });
  }

  if (path === "/v1/logout" && m === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sid).run();
    return json({ ok: true });
  }

  if (path === "/v1/sessions" && m === "GET") {
    const rows = await env.DB.prepare("SELECT id,device,created_at,last_used_at FROM sessions WHERE user_id=? AND expires_at>? ORDER BY last_used_at DESC").bind(user.id, Date.now()).all();
    return json({ ok: true, sessions: rows.results.map((s) => ({ id: s.id, device: s.device, createdAt: s.created_at, lastUsedAt: s.last_used_at, current: s.id === sid })) });
  }
  if (path === "/v1/sessions/revoke" && m === "POST") {
    const b = await readJson(req);
    const res = await env.DB.prepare("DELETE FROM sessions WHERE id=? AND user_id=?").bind(String(b.id || ""), user.id).run();
    return json({ ok: true, revoked: res.meta.changes, self: b.id === sid });
  }
  if (path === "/v1/sessions/revoke-others" && m === "POST") {
    await revokeAccess(env, user.id, { keepSid: sid, oauth: false });
    return json({ ok: true, message: "他の端末をログアウトしました" });
  }

  if (path === "/v1/points/history" && m === "GET") {
    const rows = await env.DB.prepare(
      `SELECT l.id,l.delta,l.balance_after,l.reason,l.source,l.created_at,c.name AS app_name
       FROM point_ledger l LEFT JOIN oauth_clients c ON c.id=l.actor WHERE l.user_id=? ORDER BY l.created_at DESC, l.rowid DESC LIMIT 50`
    ).bind(user.id).all();
    return json({ ok: true, points: user.points, history: rows.results.map((r) => ({ id: r.id, delta: r.delta, balanceAfter: r.balance_after, reason: r.reason, source: r.source === "admin" ? "運営" : (r.app_name || "外部アプリ"), createdAt: r.created_at })) });
  }

  // ----- 連携アプリ(ユーザーが許可したもの) -----
  if (path === "/v1/connections" && m === "GET") {
    const rows = await env.DB.prepare(
      "SELECT g.client_id,g.scopes,g.updated_at,c.name,c.description FROM oauth_grants g JOIN oauth_clients c ON c.id=g.client_id WHERE g.user_id=? ORDER BY g.updated_at DESC"
    ).bind(user.id).all();
    return json({ ok: true, connections: rows.results.map((r) => ({ clientId: r.client_id, name: r.name, description: r.description, scopes: parseScopes(r.scopes), updatedAt: r.updated_at })) });
  }
  if (path === "/v1/connections/revoke" && m === "POST") {
    const b = await readJson(req);
    const cid = String(b.clientId || "");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM oauth_grants WHERE user_id=? AND client_id=?").bind(user.id, cid),
      env.DB.prepare("DELETE FROM oauth_tokens WHERE user_id=? AND client_id=?").bind(user.id, cid),
      env.DB.prepare("DELETE FROM oauth_codes WHERE user_id=? AND client_id=?").bind(user.id, cid),
    ]);
    return json({ ok: true, message: "連携を解除しました" });
  }

  // ----- 開発者設定(自分のアプリ) -----
  if (path === "/v1/apps" && m === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM oauth_clients WHERE owner_user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ ok: true, apps: rows.results.map(appOut) });
  }
  if (path === "/v1/apps" && m === "POST") {
    const b = await readJson(req);
    const r = await limited(env, [["app-create", user.id, 10, 86400]]);
    if (r) throw tooMany(r);
    const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM oauth_clients WHERE owner_user_id=?").bind(user.id).first();
    if (cnt.n >= 5) throw bad("登録できるアプリは1アカウントにつき5件までです");
    const created = await insertClient(env, {
      name: b.name, description: b.description, redirectUris: cleanRedirects(b.redirectUris),
      scopes: devScopes(b.scopes), ownerId: user.id, createdBy: "user",
    });
    const row = await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=?").bind(created.id).first();
    return json({ ok: true, app: appOut(row), clientSecret: created.secret, message: "アプリを登録しました。クライアントシークレットはこの画面でしか表示されません" });
  }
  if (path === "/v1/apps/update" && m === "POST") {
    const b = await readJson(req);
    const c = await ownedApp(env, user.id, b.id);
    const nm = cleanText(b.name, 60);
    if (!nm) throw bad("アプリ名を入力してください");
    await env.DB.prepare("UPDATE oauth_clients SET name=?, description=?, redirect_uris=?, scopes=?, updated_at=? WHERE id=?")
      .bind(nm, cleanText(b.description, 200), JSON.stringify(cleanRedirects(b.redirectUris)), devScopes(b.scopes, c.scopes), Date.now(), c.id).run();
    const row = await env.DB.prepare("SELECT * FROM oauth_clients WHERE id=?").bind(c.id).first();
    return json({ ok: true, app: appOut(row), message: "アプリを更新しました" });
  }
  if (path === "/v1/apps/rotate" && m === "POST") {
    const b = await readJson(req);
    const c = await ownedApp(env, user.id, b.id);
    const r = await limited(env, [["app-rotate", user.id, 10, 3600]]);
    if (r) throw tooMany(r);
    return json({ ok: true, clientSecret: await rotateSecret(env, c.id), message: "シークレットを再発行しました。旧シークレットは使えなくなります" });
  }
  if (path === "/v1/apps/delete" && m === "POST") {
    const b = await readJson(req);
    const c = await ownedApp(env, user.id, b.id);
    await deleteClient(env, c.id);
    return json({ ok: true, message: "アプリを削除しました" });
  }
  return null;
}

const PUBLIC = {
  "/v1/register": register,
  "/v1/email/verify-code": verifyEmailCode,
  "/v1/login": login,
  "/v1/forgot": forgot,
  "/v1/reset": reset,
};

export async function handleV1(req, env, ctx, path) {
  const pub = PUBLIC[path];
  if (pub) {
    if (req.method !== "POST") throw bad("Method not allowed", 405);
    return pub(req, env, ctx);
  }
  const auth = await authSession(req, env);
  if (!auth) throw bad("ログインの有効期限が切れました。再ログインしてください", 401);
  const res = await authed(req, env, ctx, path, auth);
  if (!res) throw bad("Not found", 404);
  return res;
}
