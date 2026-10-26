import { readFileSync } from "node:fs";
import { createD1 } from "./d1shim.js";
import worker from "../src/index.js";

export function makeEnv() {
  return {
    DB: createD1(readFileSync(new URL("../schema.sql", import.meta.url), "utf8")),
    PASSWORD_PEPPER: "pepper-".repeat(8),
    APP_KEY: "app-key-for-tests-0123456789abcdef",
    API_BASE_URL: "https://acct.test",
    APP_RESET_URL: "https://gas.test/exec",
    ADMIN_PASSWORD: "correct horse battery staple",
    DEV_MAIL_LOG: "1",
    PBKDF2_ITERATIONS: "4000",
  };
}

export function makeClient(env) {
  const mails = [];
  const origLog = console.log;
  console.log = (...a) => {
    if (typeof a[0] === "string" && a[0].startsWith("MAIL_LOG ")) mails.push(JSON.parse(a[0].slice(9)));
    else origLog(...a);
  };
  const pending = [];
  const ctx = { waitUntil: (p) => pending.push(p) };
  const flush = async () => { while (pending.length) await pending.shift(); };

  async function call(path, { method = "GET", headers = {}, body, ip = "203.0.113.1", raw = false } = {}) {
    const init = { method, headers: { "CF-Connecting-IP": ip, ...headers } };
    if (body !== undefined) {
      if (typeof body === "string") init.body = body;
      else { init.body = JSON.stringify(body); init.headers["Content-Type"] = init.headers["Content-Type"] || "application/json"; }
    }
    const res = await worker.fetch(new Request("https://acct.test" + path, { ...init, redirect: "manual" }), env, ctx);
    await flush();
    if (raw) return res;
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch {}
    return { status: res.status, headers: res.headers, text, data };
  }
  // GAS相当(共有キー付き)
  const v1 = (path, { token, ...o } = {}) => call(path, { ...o, headers: { "X-App-Key": env.APP_KEY, ...(token ? { Authorization: "Bearer " + token } : {}), ...(o.headers || {}) } });
  const lastMail = (to) => [...mails].reverse().find((m) => m.to === to);
  const linkIn = (mail, re) => { const m = re.exec(mail.text); return m && m[0]; };
  return { call, v1, mails, lastMail, linkIn, worker, restore: () => { console.log = origLog; } };
}
