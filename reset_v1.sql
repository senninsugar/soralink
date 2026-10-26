-- v1 のテーブルを削除します(全データ消去)。
-- v1 は Workers の PBKDF2 上限(100,000回)を超える設定だったため、実環境ではユーザーを作成できていません。
-- そのため消えて困るデータは基本的にありません。v1 を適用済みの場合のみ、schema.sql の前に実行してください。
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS email_tokens;
DROP TABLE IF EXISTS users;
