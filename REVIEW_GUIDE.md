# Claude等へ渡すレビュー依頼

このファイルと `SOURCE_CODE.md`、`pyproject.toml`、`uv.lock`、`VALIDATION.md` を渡してください。実運用の `data/config.json` やメールDBは渡さないでください。

以下はLinux / WSL2で動作する「MCPサーバ機能付きポータブルWebメールクライアント」のコードです。シニアセキュリティエンジニア／バックエンドアーキテクトとして厳格に監査し、問題点・再現条件・重大度・修正コード・回帰テストを提示してください。

1. **SQLiteのロック競合・並行性**
   - 全接続のWAL、busy_timeoutと短い書き込みトランザクション。
   - Web同期と複数stdioプロセスの並行性、複数Web起動の排他。
   - UIDVALIDITY変更の原子的反映、クラッシュ時の整合性、バックアップ手順。
   - SMTP直前の送信権取得、重複クリック、部分拒否、送信結果不明時の再送防止。
2. **日本語MIMEデコード耐性**
   - UTF-8、ISO-2022-JP、Shift_JIS／CP932、EUC-JP、不正charset、壊れたDate／ヘッダー。
   - multipart/alternative、添付message/rfc822、巨大／深いMIME、HTML-onlyメール。
   - 1件の不正メールが以後の同期を妨げないか。
3. **IMAP固有の仕様**
   - SPECIAL-USEのDrafts検出、サーバー固有名、modified UTF-7。
   - APPENDの\\DraftフラグとCRLF。保存結果不明時の扱い。
   - UID再利用、EXPUNGE競合、BODY.PEEK、既読フラグ同期、フォルダ障害の分離。
4. **セキュリティ**
   - HTMLの空sandbox、srcdoc、iframe内部CSPとサニタイズ、外部画像・CSS・自動遷移。
   - 親画面に未信頼データを挿入する全箇所、DOM XSS／HTMLパーサー差分。
   - MCP／Webトークン分離、認証漏れ、CSRF／Origin／Host、DNS rebinding。
   - ヘッダーインジェクション、Bcc除去、送信前の宛先／本文確認。
   - MCPに送信ツールがなく、未信頼データ境界をエスケープしているか。
   - パストラバーサル、認証情報のログ漏えい、巨大HTTP／IMAP応答によるDoS。
   - タグ付けでは完全防止できないプロンプトインジェクション、ローカルOS権限の限界。
5. **ポータブル性**
   - アプリデータがプロジェクトdata/配下に収まり、任意cwdで一致するか。
   - uv／Pythonのキャッシュと一時ファイルがホーム設定ディレクトリへ書かれないか。
   - コピー後の仮想環境再作成、WALの移行、Linux／WSL2権限の差。
6. **実装と説明の一致**
   - MCP SDK固定バージョンとstdio／Streamable HTTP接続の互換性。
   - テスト済み範囲と未検証の実サーバー／Linux実機を混同していないか。
   - 初版の制約がユーザーへ明示されているか。

レビュー結果は重大度順にまとめ、問題がなかった観点も検証根拠とともに記載してください。実アカウントへの送信は行わず、必要ならテスト用のモックまたは隔離サーバーを使用してください。
