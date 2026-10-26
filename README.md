# Sennin Account v2 — Cloudflare Workers + D1 + Google Apps Script

```
ブラウザ ─ GAS(Index.html / Code.gs: 画面+中継) ─► Worker /v1/*  (共有キー APP_KEY 必須)
外部アプリ ───────────────────────────────────► Worker /oauth/*, /api/v1/*
管理者 ───────────────────────────────────────► Worker /admin  (ADMIN_PASSWORD)
```

## 今回の対応
| 要望 | 実装 |
|---|---|
| レート制限 | D1の固定ウィンドウ(下表)。管理者ログインは失敗回数でロック |
| メール変更の再確認 | パスワード必須 → **新アドレス**へ確認リンク → 旧アドレスへ通知 → 確定で全端末ログアウト |
| パスワード再設定画面 | GASに再設定画面を追加(メールのリンク → 新パスワード)。完了で全セッション/OAuthトークン失効 |
| 認証・セッション検証 | 下の「セキュリティ検証結果」参照(重大な問題を複数修正) |
| メールはResend | 確認・再設定・変更確認・各種通知(HTMLエスケープ済み) |
| 開発者設定/OAuth 2.0 | アカウント画面「開発者設定」でアプリ登録、client_id/secret発行(シークレットは1度だけ表示・ハッシュ保存)。認可コード+PKCE、refreshローテーション |
| 管理者パネル | `https://<Worker>/admin` → パスワード → ユーザー確認/検索、ポイント付与・減算、**一括配布**、BAN/解除、強制ログアウト、アプリ管理、監査ログ |
| ポイント管理アプリは管理者のみ | スコープ `points:write` は**管理者パネルからのみ**付与可。開発者設定では選べず、APIで要求しても403 |

## セットアップ
```bash
npm i -g wrangler && wrangler login
wrangler d1 create sennin-account            # database_id を wrangler.toml に記入
wrangler d1 execute sennin-account --remote --file=./schema.sql
#   ※旧v1スキーマを適用済みなら、先に --file=./reset_v1.sql を実行
```
`wrangler.toml` の `API_BASE_URL`(WorkerのURL)と `APP_RESET_URL`(GASの/exec URL)を設定し、シークレットを登録:
```bash
wrangler secret put PASSWORD_PEPPER   # 32文字以上のランダム。★設定後は変更不可(変えると全員ログイン不能)
wrangler secret put APP_KEY           # 24文字以上のランダム。GASと同じ値
wrangler secret put RESEND_API_KEY
wrangler secret put MAIL_FROM         # 例: Sennin Account <account@your-domain.example> (Resendでドメイン検証済み)
wrangler secret put ADMIN_PASSWORD    # 16文字以上推奨(12文字未満だと /admin は無効=404)
wrangler deploy
```
GAS: `Code.gs` と `Index.html` を貼り付け → スクリプトプロパティに `API_BASE_URL` と `APP_KEY` → ウェブアプリとしてデプロイ → `/exec` URL を `APP_RESET_URL` に入れて `wrangler deploy` し直す。

## レート制限
GAS(UrlFetchApp)経由はGoogleのIPから届くため、`/v1/*` は**IPではなくメール/ユーザー/全体**で制限します。直接アクセスされる `/oauth/*` と `/admin` はIPで制限します。

| 対象 | 制限 |
|---|---|
| ログイン(メール単位) | **失敗10回/15分**でロック(正しいPWでも拒否)。成功は数えない |
| 登録 / 再設定依頼 | メールごと3回/時間、全体300・200回/時間 |
| メール変更 / パスワード変更 | 3回/時間 / 現PW失敗10回/15分 |
| OAuth認可・トークン | IPごと30(POST)/120(GET) 回/10分、トークン120回/分、クライアントごと300回/分 |
| ポイントAPI | クライアントごと600回/分 + アプリごとの24時間増減上限 |
| `/admin` ログイン | IPごと失敗5回/15分、全体で失敗30回/時間 |
既知のトレードオフ: メール単位ロックは、他人が故意に失敗を重ねると15分間そのメールのログインを妨げられます(総当たり防止との引き換え)。

## セッションとOAuth画面
- アカウントセッションはサーバー側DBで管理し、ログイン時から14日間有効(ブラウザを閉じても保持)。ログアウト・BAN・パスワード変更等による失効は維持。デプロイ後もまだ有効な旧7日セッションは作成時刻から14日まで延長し、期限切れセッションは復活させない。
- GASのOAuth画面は、保存済みセッションが有効なら利用アカウントを確認し、「このアカウントで続行」または「別のアカウントを使用」を選べる。初回/未ログイン時はログイン・新規登録を選び、新規登録はメール認証コードで確認する。
- OAuthコールバックには `code` と `state` など必要な結果だけを返し、`iss` クエリパラメータは追加しない。

## セキュリティ検証結果(旧版の問題と対応)
1. **【重大】ログアウト/パスワード変更しても7日間JWTが有効**だった(DBのセッションを確認していない) → 不透明トークン+DB照合に変更。ログアウト・BAN・変更で即失効。
2. **【重大】GASが `getUserProperties()` にトークン保存** → 「実行ユーザー: 自分」だと全訪問者が同一セッションを共有。→ トークンはブラウザ側保持、GASはステートレス中継に。
3. **【重大】PBKDF2 210,000回はWorkersの上限(100,000)超過**で登録/ログインが例外になる → 反復回数を設定可能にし、サーバー秘密(ペッパー)でHMACしてから導出(下の「無料プラン対応」参照)。
4. APP_KEY が実際には検証されていなかった → 未設定/不一致は拒否(fail closed)。
5. 登録/再設定/メール変更でのアカウント存在の推測(列挙)、ログイン時間差 → 同一応答・同一計算コスト。
6. 未確認アカウントの事前乗っ取り → 再登録は最新で上書きし旧リンク無効化。
7. メールのリンクはGETで消費せず確認ボタン経由(プリフェッチ対策)。メール本文はHTMLエスケープ。
8. 内部エラー文をクライアントに返していた → 汎用メッセージ化(詳細はログのみ)。`/v1/*` のCORS全開を撤廃。
9. 登録画面のパスワード欄にIDが無く登録が常に失敗、ログイン欄にテスト用の初期値(`password123`)が入っていた → 修正。
10. GASの再設定トークンはURL由来のため、形式をホワイトリスト検証してから埋め込み(XSS対策)。
11. 管理者: Cookie(HttpOnly/Secure/SameSite=Strict)+CSRFトークン+Origin検証、nonce付きCSP、全操作を監査ログ記録。管理画面は `innerHTML` 不使用。

## Workers 無料プラン対応
- **CPU 10ms/リクエスト**: PBKDF2 は 100,000 回で約 50〜60ms かかり枠を超えるため、反復回数を `PBKDF2_ITERATIONS`(既定 **4000** ≒ 約3ms、SHA-512)にしました。実測値は Node での計測で、Cloudflare 上の実測ではありません。デプロイ後に Workers のメトリクスで CPU 時間を確認してください(超過なら 3000 に下げる)。
- 反復回数が低い分は、①DBに入らないサーバー秘密 `PASSWORD_PEPPER` で HMAC してから導出、②失敗10回/15分のロック、③12文字以上必須、で補います。ただし**DBとペッパーの両方が漏れた場合は総当たりに弱く**なります。
- **有料プランへ移行したら** `wrangler.toml` の `PBKDF2_ITERATIONS` を `"100000"`(Workersの上限)に上げて再デプロイ。各ユーザーのハッシュは次回ログイン時に自動で強化されます。
- **subrequest 50回/リクエスト**: 管理者の個別配布(最大100件)が1件ずつSELECTしていたのを1クエリに変更。他の処理は最大でも約10回です。
- その他の無料枠(Worker 10万リクエスト/日、D1 読み取り500万行・書き込み10万行/日、サイズ3MB、cron)内で動く構成です。

## OAuth の動作確認ページと、AI向け仕様書
- **確認ページ**: `https://<Worker>/oauth-test` — 認可 → トークン交換(PKCE) → userinfo/ポイントAPI → リフレッシュ → 失効 までブラウザで試せます。先にアプリを登録し、リダイレクトURIに `https://<Worker>/oauth-test` を**そのまま**入れてください。
- **AI向け仕様書**: `https://<Worker>/llms.txt`(Markdown)。このURLを他のAIに渡すか、同梱の `API.md` を読ませれば、APIの使い方が全てわかります。
- 仕様書を直したいときは `docs/api.template.md` を編集 → `node scripts/build-docs.mjs https://<WorkerのURL>` → `wrangler deploy`。

## OAuth(外部アプリ向け)
- 認可: `GET /oauth/authorize?response_type=code&client_id=…&redirect_uri=…&scope=profile email&state=…&code_challenge=…&code_challenge_method=S256`
- トークン: `POST /oauth/token` (`grant_type=authorization_code|refresh_token`、client_secret_basic/post)。アクセス1時間/リフレッシュ30日(使うたびに更新)。
- `GET /oauth/userinfo`, `GET /api/v1/points`(points:read), `POST /api/v1/points/adjust`(points:write):
  `{"amount":100,"reason":"…","idempotency_key":"一意な8〜64文字"}` — 冪等・残高不足は409・24時間上限超過は429。
- スコープ: `profile` / `email` / `points:read`(誰でも) / `points:write`(**管理者のみ**)。管理者が後で外すと発行済みトークンにも即反映。
- リダイレクトURIは完全一致のみ(httpsとlocalhostのhttp)。登録外URIには絶対にリダイレクトしません。

## テスト
`npm test`(Node 22+)。Node標準SQLiteでD1を模擬し、登録〜OAuth〜ポイント〜管理者〜BANまで22項目を検証します。

## 未確認・注意(正直に)
- **実際のCloudflare(workerd/D1)とResendでは未実行**です(作業環境からnpm/Cloudflareに接続できず)。ロジックはテストで検証済みですが、デプロイ後に `wrangler dev` または本番で、登録→メール→ログイン→OAuth→管理画面を一度通してください。
- Worker無料枠のD1書き込み(日10万行)・リクエスト(日10万)と、GASのUrlFetch日次上限は、大量アクセス時の上限になります。
- 二段階認証は未実装(画面に「未対応」表示)。メール変更後・PW再設定後は全端末ログアウトされます。
- 管理画面はパスワードのみ。公開前に Cloudflare Access(Zero Trust)で `/admin*` を保護する二重化を推奨します。


## 仕様変更メモ（2026-10-23）

### メール認証コード

- 新規登録後、メールに6桁の認証コードを送信します。コードは10分間有効です。
- `email_codes` テーブルにはコードそのものではなく SHA-256 ハッシュを保存します。
- `/v1/email/verify-code` を GAS の `verifyEmailCode` アクション経由で呼び出します。
- コード試行回数は5回までで、IP/メールアドレス単位のレート制限を適用します。
- データベースには `schema.sql` の更新を適用してください。

### OAuth 認可画面について

このアーカイブの OAuth 認可エンドポイントは従来どおり Worker の `/oauth/authorize` です。GAS のアカウント画面から Worker URL を `CFG` に埋め込まない変更は行っていますが、OAuth 認可画面そのものを GAS に移す作業は未完了です。認可画面を本当に GAS のみで表示し、Worker URL をブラウザに露出させないためには、Worker 側に「クライアント情報の取得」「ユーザー認証・同意の確定」「認可コード発行」を行う内部 API を追加し、GAS からサーバー間通信する構成への追加移行が必要です。現段階でこのアーカイブを OAuth 認可画面まで完全移行済みとして本番公開しないでください。
