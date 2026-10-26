-- Sennin Account schema (v2)
-- 新規セットアップ: wrangler d1 execute sennin-account --remote --file=./schema.sql
-- v1(旧スキーマ)適用済みの場合は先に reset_v1.sql を実行してください。

CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,                       -- v1$<iter>$<salt>$<hash>
  email_verified INTEGER NOT NULL DEFAULT 0,
  points         INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','banned')),
  ban_reason     TEXT,
  banned_at      INTEGER,
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at);

CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  device       TEXT,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- メール確認 / パスワード再設定用ワンタイムトークン(ハッシュのみ保存)
CREATE TABLE IF NOT EXISTS email_tokens (
  id         TEXT NOT NULL,                           -- user id
  token_hash TEXT NOT NULL,
  purpose    TEXT NOT NULL,                           -- 'verify' | 'reset'
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(id, purpose)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_tokens_hash ON email_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_email_tokens_expiry ON email_tokens(expires_at);

-- メール認証コード(6桁、ハッシュのみ保存、10分有効、最大5回試行)
CREATE TABLE IF NOT EXISTS email_codes (
  email        TEXT NOT NULL,
  purpose      TEXT NOT NULL CHECK (purpose IN ('verify','change_email')),
  code_hash    TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_sent_at INTEGER NOT NULL,
  PRIMARY KEY(email, purpose)
);
CREATE INDEX IF NOT EXISTS idx_email_codes_expiry ON email_codes(expires_at);

-- メールアドレス変更(新アドレスでの再確認待ち)
CREATE TABLE IF NOT EXISTS email_changes (
  user_id    TEXT PRIMARY KEY,
  new_email  TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ポイント台帳(全ての増減を記録)
CREATE TABLE IF NOT EXISTS point_ledger (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  delta         INTEGER NOT NULL,
  balance_after INTEGER NOT NULL,
  reason        TEXT NOT NULL,
  source        TEXT NOT NULL,                        -- 'admin' | 'app'
  actor         TEXT NOT NULL,                        -- 'admin' | client_id
  idem_key      TEXT,
  created_at    INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON point_ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_actor ON point_ledger(actor, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_idem ON point_ledger(actor, idem_key) WHERE idem_key IS NOT NULL;

-- OAuth 2.0 クライアント(外部アプリ)
CREATE TABLE IF NOT EXISTS oauth_clients (
  id                 TEXT PRIMARY KEY,                -- client_id
  secret_hash        TEXT NOT NULL,
  name               TEXT NOT NULL,
  description        TEXT NOT NULL DEFAULT '',
  owner_user_id      TEXT,                            -- NULL = 管理者が登録
  redirect_uris      TEXT NOT NULL,                   -- JSON array
  scopes             TEXT NOT NULL,                   -- 許可スコープ(空白区切り)。points:write は管理者のみ付与可
  points_daily_limit INTEGER NOT NULL DEFAULT 10000,  -- points:write アプリの24時間あたり増減上限(絶対値合計)
  status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by         TEXT NOT NULL DEFAULT 'user',    -- 'user' | 'admin'
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_clients_owner ON oauth_clients(owner_user_id);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash      TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  user_id        TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  scopes         TEXT NOT NULL,
  code_challenge TEXT,
  expires_at     INTEGER NOT NULL,
  FOREIGN KEY(client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  id              TEXT PRIMARY KEY,
  access_hash     TEXT NOT NULL UNIQUE,
  refresh_hash    TEXT NOT NULL UNIQUE,
  client_id       TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  scopes          TEXT NOT NULL,
  access_expires  INTEGER NOT NULL,
  refresh_expires INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  FOREIGN KEY(client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON oauth_tokens(user_id, client_id);

-- ユーザーが許可した連携アプリ
CREATE TABLE IF NOT EXISTS oauth_grants (
  user_id    TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  scopes     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, client_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE
);

-- 管理者セッション / 監査ログ
CREATE TABLE IF NOT EXISTS admin_sessions (
  id         TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  csrf       TEXT NOT NULL,
  ip         TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_audit (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON admin_audit(ts DESC);

-- レート制限(固定ウィンドウ)
CREATE TABLE IF NOT EXISTS rate_limits (
  key          TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_limits(window_start);
