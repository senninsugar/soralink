# Sennin Account — OAuth 2.0 / API 仕様書 (AI・開発者向け)

この文書は **Sennin Account** の認可サーバー(OAuth 2.0)とリソースAPIの完全な仕様です。
他のAIや開発者は、この文書だけで「アプリの登録 → ユーザー認可 → トークン取得 → API利用」まで実装できます。

- **Base URL**: `{{BASE}}`
- 認可方式: OAuth 2.0 **認可コードフロー** + **PKCE(S256)**。トークン形式は不透明文字列(JWTではない)。
- すべてのエンドポイントはHTTPS。文字コードはUTF-8。レスポンスはJSON(認可画面のみHTML)。
- 動作確認ページ: `{{BASE}}/oauth-test` (ブラウザで認可〜API呼び出しまで試せる)
- 機械可読メタデータ: `{{BASE}}/.well-known/oauth-authorization-server`

---

## 1. 最短手順 (Quick start)

1. **アプリを登録する** — ユーザーがアカウント画面(GAS)の「開発者設定」で登録(名前・リダイレクトURI・スコープ)。`client_id` と `client_secret` が発行される(**シークレットは登録直後に1度だけ表示**)。
   - `points:write`(ポイント加算・減算)は **管理者だけが付与できる**。開発者設定では選べない。必要なら管理者に依頼する。
2. **ユーザーを認可画面へ送る**: `GET {{BASE}}/oauth/authorize?...`(§4.1)。ユーザーがメール+パスワードでログインして「許可する」を押すと、`redirect_uri?code=...&state=...` に戻される。
3. **認可コードをトークンに交換**: `POST {{BASE}}/oauth/token`(§4.2)。`access_token`(1時間)と`refresh_token`(30日)が返る。
4. **APIを呼ぶ**: `Authorization: Bearer <access_token>` を付けて `GET {{BASE}}/oauth/userinfo` など(§5)。
5. 期限切れ(401)になったら `refresh_token` で更新(§4.3)。

---

## 2. スコープ

| スコープ | 内容 | 付与できる人 |
|---|---|---|
| `profile` | ユーザーID(`sub`)と名前の参照 | 開発者 |
| `email` | メールアドレスと確認状態の参照 | 開発者 |
| `points:read` | ポイント残高の参照 | 開発者 |
| `points:write` | ポイントの加算・減算(`points:read`も実質含む) | **管理者のみ** |

- スコープは空白区切り(例: `profile email`)。省略時は `profile`。
- 認可リクエストで要求できるのは **アプリに許可されたスコープだけ**。それ以外は `invalid_scope`。
- 実際に使える権限 = `トークンのスコープ ∩ アプリの現在の許可スコープ`。管理者が後からスコープを外すと、**発行済みトークンにも即時反映**される。

---

## 3. 共通ルール

| 項目 | 値 |
|---|---|
| 認可コード | 有効10分・**1回限り**(使うと、失敗しても消える) |
| アクセストークン | 有効 **1時間**。接頭辞 `sat_` |
| リフレッシュトークン | 有効 **30日**。**使うたびに新しいものに交換(ローテーション)**。旧いものは即無効。接頭辞 `srt_` |
| 同一ユーザー×アプリのトークン | 最大5組(古いものから失効) |
| PKCE | `code_challenge_method=S256` のみ。`code_verifier` は43〜128文字の `[A-Za-z0-9-._~]` |
| リダイレクトURI | 登録済みURIとの**完全一致**のみ。`https://`、または `http://localhost` / `127.0.0.1` / `[::1]`。最大5件、フラグメント(#)不可 |
| クライアント認証 | `client_secret_basic`(Basicヘッダ) または `client_secret_post`(ボディ) |
| CORS | `/oauth/token` `/oauth/revoke` `/oauth/userinfo` `/api/v1/*` は `Access-Control-Allow-Origin: *`(Cookie不使用。Bearerのみ) |

**ユーザーの資格情報はアプリ側で入力・取得しない**。GASフロントエンドの認可画面では、既存のログインセッションが有効ならアカウントを確認して続行でき、別アカウントへの切替もできる。未ログイン時はログインまたは新規登録(メール認証コード)を選択できる。通常のアカウントセッションはサーバー管理で最大14日間有効。

---

## 4. 認可サーバー

### 4.1 `GET {{BASE}}/oauth/authorize` — 認可リクエスト
ブラウザ(ユーザーエージェント)で開く。ログイン+同意画面(HTML)が表示される。

| パラメータ | 必須 | 説明 |
|---|---|---|
| `response_type` | ○ | `code` 固定 |
| `client_id` | ○ | 発行された `sa_...` |
| `redirect_uri` | △ | 登録済みURIのいずれか(完全一致)。アプリにURIが1つだけなら省略可 |
| `scope` | | 空白区切り。省略時 `profile` |
| `state` | 強く推奨 | CSRF対策。そのまま返される。**必ず検証すること** |
| `code_challenge` | 推奨 | `BASE64URL(SHA256(code_verifier))`(43文字)。指定した場合は交換時に `code_verifier` 必須 |
| `code_challenge_method` | `code_challenge`指定時○ | `S256` のみ(`plain`は拒否) |

**結果(ユーザーのブラウザが `redirect_uri` にリダイレクトされる / HTTP 303)**。コールバックURLには `iss` クエリパラメータを追加しない。
- 成功: `redirect_uri?code=sac_...&state=...`
- 失敗/拒否: `redirect_uri?error=...&error_description=...&state=...`
  - `access_denied`(ユーザーがキャンセル)、`invalid_scope`、`invalid_request`(PKCE不正)、`unsupported_response_type`
- **`client_id` が無効・無効化済み、または `redirect_uri` が未登録の場合は、リダイレクトせず**エラー画面(HTTP 400)を表示する(オープンリダイレクト対策)。
- BAN中/メール未確認のユーザーは認可画面でログインに失敗する(403)。

### 4.2 `POST {{BASE}}/oauth/token` — 認可コードをトークンに交換
`Content-Type: application/x-www-form-urlencoded`(JSONも可)。

```
grant_type=authorization_code
code=sac_...
redirect_uri=<認可リクエストと同じ値>
code_verifier=<PKCE使用時>
client_id=sa_...            # Basic認証を使わない場合
client_secret=sas_...       # Basic認証を使わない場合
```
成功 (200):
```json
{
  "access_token": "sat_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "srt_...",
  "scope": "profile email"
}
```
- `scope` は実際に付与されたスコープ(要求より少ない場合がある)。
- レスポンスは `Cache-Control: no-store`。

### 4.3 `POST {{BASE}}/oauth/token` — リフレッシュ
```
grant_type=refresh_token
refresh_token=srt_...
client_id=... & client_secret=...   (または Basic)
```
成功時は §4.2 と同じ形式。**新しい `refresh_token` が返り、古いものは使えなくなる**(必ず保存し直すこと)。

### 4.4 トークンエンドポイントのエラー
```json
{ "error": "invalid_grant", "error_description": "..." }
```
| HTTP | error | 意味 |
|---|---|---|
| 401 | `invalid_client` | client_id/secret が違う、またはアプリが無効化されている |
| 400 | `invalid_grant` | コードが無効・期限切れ・使用済み、redirect_uri不一致、PKCE検証失敗、リフレッシュトークン無効、ユーザーがBAN/スコープが空 |
| 400 | `unsupported_grant_type` | `authorization_code` / `refresh_token` 以外 |
| 429 | `temporarily_unavailable` | レート制限。`Retry-After` 秒待つ |

### 4.5 `POST {{BASE}}/oauth/revoke` — トークン失効 (RFC 7009)
クライアント認証 + `token=<access または refresh トークン>`。常に200 `{}`(存在しないトークンでも)。

---

## 5. リソースAPI (`Authorization: Bearer sat_...`)

### 5.1 `GET {{BASE}}/oauth/userinfo` (別名 `GET {{BASE}}/api/v1/me`)
トークンのスコープに応じた項目だけを返す。
```json
{ "sub": "<ユーザーID(UUID)>", "name": "...", "email": "...", "email_verified": true, "points": 1200 }
```
- `name` は `profile`、`email` と `email_verified` は `email`、`points` は `points:read` または `points:write` がある場合のみ。
- `sub` は常に返る。**ユーザーの識別には `sub` を使うこと**(メールや名前は変わりうる)。

### 5.2 `GET {{BASE}}/api/v1/points` — 残高
要 `points:read` または `points:write`。
```json
{ "ok": true, "points": 1200 }
```

### 5.3 `POST {{BASE}}/api/v1/points/adjust` — ポイント加算・減算
要 **`points:write`**(管理者承認済みアプリのみ)。`Content-Type: application/json`。
```json
{ "amount": 100, "reason": "ミッション報酬", "idempotency_key": "mission-2026-10-22-u123" }
```
| フィールド | 説明 |
|---|---|
| `amount` | **0以外の整数**。正=加算、負=減算。絶対値は「アプリの上限」以下(既定10,000。管理者が設定) |
| `reason` | 必須(最大100文字)。ユーザーのポイント履歴に表示される |
| `idempotency_key` | 必須。8〜64文字の `[A-Za-z0-9_.:-]`。**同じ操作の再送には同じキーを使う**。アプリごとに一意 |

成功 (200):
```json
{ "ok": true, "points": 1300, "ledger_id": "..." }
```
同じ `idempotency_key` + 同じ内容の再送は **二重に加算されず**、`{"ok":true,"replayed":true,"points":1300,"ledger_id":"..."}` を返す。

エラー:
| HTTP | `error` | 意味 |
|---|---|---|
| 400 | `error` | 入力不正(amountが整数でない/0/上限超過、reasonなし、keyの形式不正) |
| 401 | `invalid_token` | トークンが無効・期限切れ・失効、ユーザーがBAN、アプリが無効 → リフレッシュ or 再認可 |
| 403 | `insufficient_scope` | `points:write` が無い(アプリに未承認、またはユーザーが同意していない) |
| 409 | `insufficient_points` | 残高不足(減算で0未満になる)。`points`に現在残高。**何も変更されない** |
| 409 | `error` | 同じ `idempotency_key` が別の内容(別ユーザー/別amount)で使われている |
| 429 | `daily_limit_exceeded` | このアプリの**24時間あたりの増減上限(絶対値の合計)**に達した。`used` と `limit` を返す |
| 429 | `error` | レート制限(クライアントあたり600回/分)。`retryAfter` 秒待つ |

エラー本文の形式: `{ "ok": false, "error": "<コード>", "error_description": "<日本語の説明>", ... }`。
`401` は `{ "error": "invalid_token", "error_description": "..." }` + `WWW-Authenticate: Bearer error="invalid_token"`。

- 残高は **0未満にならない**。台帳(履歴)に全ての増減が記録され、ユーザーはアカウント画面で確認できる。
- 判定は原子的(残高・上限・BAN判定と更新が同時に行われる)。

### 5.4 `GET {{BASE}}/.well-known/oauth-authorization-server`
OAuthメタデータ(issuer、各エンドポイント、対応スコープ、`code_challenge_methods_supported: ["S256"]` など)。

---

## 6. 実装例

### 6.1 PKCE + 認可URL (JavaScript)
```js
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const verifier = b64u(crypto.getRandomValues(new Uint8Array(48)));
const challenge = b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
const state = b64u(crypto.getRandomValues(new Uint8Array(16)));
// verifier と state を保存(サーバーのセッション等)してから:
const url = "{{BASE}}/oauth/authorize?" + new URLSearchParams({
  response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
  scope: "profile email points:read", state, code_challenge: challenge, code_challenge_method: "S256",
});
location.href = url;
```

### 6.2 コード交換 (curl)
```bash
curl -sS -X POST {{BASE}}/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri="$REDIRECT_URI" \
  -d code_verifier="$VERIFIER"
```

### 6.3 API呼び出し
```bash
curl -sS {{BASE}}/oauth/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"

curl -sS -X POST {{BASE}}/api/v1/points/adjust \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"amount":100,"reason":"ミッション報酬","idempotency_key":"mission-0001-u123"}'
```

### 6.4 リフレッシュ (Python)
```python
import requests
r = requests.post("{{BASE}}/oauth/token", auth=(CLIENT_ID, CLIENT_SECRET),
                  data={"grant_type": "refresh_token", "refresh_token": refresh_token})
tok = r.json()           # 新しい refresh_token が入っている。必ず保存し直す
```

### 6.5 401/429 の扱い (推奨ロジック)
```
API呼び出し → 401 invalid_token なら refresh → 成功したら1回だけ再実行 → refreshも invalid_grant なら再認可(ユーザーに再ログインを依頼)
429 → Retry-After / retryAfter 秒待って再試行(ポイント加算は必ず同じ idempotency_key で)
ネットワーク失敗でポイント加算の結果が不明 → 同じ idempotency_key で再送(二重加算されない)
```

---

## 7. 実装者への必須ルール (AIへの指示)

1. **`client_secret` はサーバー側にのみ置く**。ブラウザ/モバイルアプリに埋め込まない。公開クライアントでは使わない(この認可サーバーは全クライアントが機密クライアント前提)。
2. **必ず `state` を生成・検証**し、可能な限り **PKCE(S256)** を使う。
3. トークン・シークレット・認可コードを**ログに出さない**。URLに残さない。
4. ユーザーの識別は `sub`。メールを主キーにしない。
5. ポイント加算・減算は**必ず `idempotency_key` を付ける**。リトライ時は同じキー。キーは「操作ごとに一意かつ再送では不変」(例: 注文ID、ミッションID+ユーザーID)。
6. `points:write` が必要な機能を作る場合、**アプリに管理者の承認が必要**であることをユーザー/管理者に案内する(自分で付与しようとしない)。
7. `refresh_token` は使うたびに入れ替わる。**古い値を保持し続けない**。同じリフレッシュトークンの並行使用は避ける。
8. ユーザーはいつでも「連携アプリ」画面から許可を取り消せる。取り消されるとトークンは即無効(401)になる。
9. このAPIは `/v1/*`(アカウント画面用内部API)・`/admin*`(管理者用)を**外部アプリに公開していない**。使うのは `/oauth/*`、`/api/v1/*`、`/.well-known/*` のみ。

---

## 8. レート制限・上限まとめ

| 対象 | 制限 |
|---|---|
| `/oauth/authorize` | IPごと 30回(POST)/120回(GET) / 10分 |
| `/oauth/token` | IPごと120回/分、クライアントごと300回/分 |
| 認可画面のログイン | メールごとに失敗10回/15分でロック |
| `/api/v1/points/adjust` | クライアントごと600回/分 + アプリごとの24時間増減上限(管理者設定、既定10,000) |

---

## 9. トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| 認可画面ではなく「リクエストが無効です」 | `client_id` の誤り/アプリ無効化、または `redirect_uri` が登録と完全一致していない(末尾スラッシュ・ポート・大文字小文字) |
| `redirect_uri?error=invalid_scope` | アプリに許可されていないスコープを要求した。開発者設定で選べるのは `profile` `email` `points:read` のみ |
| `invalid_grant` | コードの再利用/期限切れ/`redirect_uri`や`code_verifier`の不一致。コードは1回限りなので最初からやり直す |
| `invalid_client` | `client_secret` の誤り(再発行後は旧シークレット無効)、またはアプリが管理者に無効化された |
| `403 insufficient_scope` | `points:write` 未承認(管理者に依頼)、またはユーザー同意時に `points:write` を要求していない |
| ユーザーがログインできない | メール未確認、BAN中、または失敗10回で15分ロック中 |
