# 検証結果

実施日: 2026-11-14（Asia/Tokyo）

## 実行済み

- WindowsホストのPython 3.12.14で、`uv.lock` から独立した仮想環境を構築。
- pytest: **33 passed**（初版17件＋レビュー指摘の回帰テスト16件 `tests/test_review_fixes.py`）。
- SQLite: 3個の別プロセスによる並行書き込み／読み取りと `integrity_check=ok`。
- 同じ下書きに8個の同時送信権取得要求を実行し、1個だけ成功。
- 日本語文字コード5種類、不正charset、JIS件名、壊れたDate、multipart添付除外。
- UIDVALIDITY変更、キャッシュ削除反映、未読数、SQLワイルドカードのリテラル検索、スレッドのアカウント分離。
- IMAP SPECIAL-USE日本語下書き名、APPENDのDraftフラグ、CRLF。
- SMTP Bcc除去、部分拒否、DATA受理後のQUIT失敗、結果不明時の自動再送防止（モック）。
- HTTP: Host／Origin／認証、MCPトークンによるWeb送信拒否、リクエストサイズ制限。
- MCP: 実際のstdioサブプロセスでinitialize／tools/list／tools/call、存在しないsend_emailの拒否。
- MCP: ASGI TestClient経由の `/mcp` initialize／tools/list／tools/call。

### レビュー指摘の修正に対する回帰テスト

- ISO-2022-JPのNEC特殊文字（①、㈱）を本文・件名で復号、半角カナ、生8bit Shift_JISヘッダーと宛先名、charset未指定EUC-JP、iso-8859-1誤宣言Shift_JIS、正しいlatin-1の非破壊。
- RFC 2047表示名による宛先注入が表示・送信のどちらにも現れないこと、2つのパーサーが不一致なら送信拒否。
- SMTP認証失敗は「未送信」として送信権を解放し再送可能、送信元不一致は送信権を消費しない、DATA中の切断は `unknown`。
- パーサー例外を起こすメールはプレースホルダー化、IMAP通信エラーはプレースホルダー化しない。
- 存在しないフォルダがあっても他フォルダを同期、1アカウント1接続。
- サイズ上限引き上げ後のプレースホルダー再取得、既読フラグは変化行のみ更新。
- 旧形式DBのキャッシュ再構築（送信記録は保持）と再初期化の冪等性、スレッド連鎖。
- 無効化アカウントのキャッシュ済みメール閲覧、Webサーバー二重起動時の明示エラー。

依存ライブラリ由来の警告2件: Starlette TestClientのhttpx利用に関する非推奨警告、MCP v1.26.0と現行pydantic-settingsのlifespan型前方参照に関する警告。テスト失敗はありません。

## 未検証・制約

- このホストではWSL実行がアクセス拒否となるため、Linux／WSL2実機での起動と `run.sh` の `/mnt` 警告は未確認です。
- 実IMAP／SMTPサービスへの接続、実アカウント認証、実メール送信は行っていません。
- 画面描画・iframe隔離の実ブラウザ検証は未完了です。今回の `static/app.js` 変更（自動更新時のページ保持、同期エラー解除表示）も実ブラウザでは未確認で、このホストにNode.jsがないため構文チェックも未実施です。
- SQLite／MIME／認証／MCPテストは実コードを実行しています。IMAP／SMTP外部サーバー挙動のテストはモックです。

Linux / WSL2の実環境では `bash run.sh --test` の後、テスト用アカウントで受信・下書き保存・送信を確認してください。
