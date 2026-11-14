# MCP Webmail — Linux / WSL2 用ポータブルWebメール

Python 3.11以上と `uv` で動作する、ローカル専用のIMAPメールキャッシュ／WebメールUI／MCPサーバーです。MCPでできる操作は検索・参照・下書き保存までです。送信はWeb UIで下書きを開き、宛先・本文を確認して実行します。

## 構成

```text
mcp-webmail/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── db.py
│   ├── mail_parser.py
│   ├── imap_sync.py
│   ├── smtp_client.py
│   ├── mcp_server.py
│   └── main.py
├── static/
│   ├── index.html
│   └── app.js
├── tests/
│   ├── conftest.py
│   ├── test_core.py
│   ├── test_mail_servers.py
│   └── test_transports.py
├── data/                  # 初回起動でconfig.json/mail.db等を生成
├── pyproject.toml
├── uv.lock                # 依存バージョン・ハッシュを固定
├── run.sh
├── README.md
└── REVIEW_GUIDE.md
```

UIは3ペイン構成です。追加のJS 1ファイルとインラインCSSを使用します。Tailwind CDNは使わず、オフライン表示と厳しいContent Security Policyを優先しました。

## 起動

LinuxまたはWSL2のLinuxファイルシステム上へ展開してください。WSLでは `/mnt/c` より `~/projects` 等のLinux側の任意の作業フォルダが適しています。アプリはホーム設定ディレクトリへ書き込みません。

前提: Python 3.11以上、`uv`、Bash、Linuxの `readlink`、信頼済みCA証明書。`uv` がPATHにない場合は、uv実行ファイルをプロジェクト内へ配置し、そのディレクトリをPATHへ追加できます。uv自身のインストーラは本プロジェクトには含みません。

```bash
cd mcp-webmail
bash run.sh
```

初回に `data/config.json` を作成します。最初のサンプルアカウントは無効です。Ctrl+Cで停止し、設定を編集して再起動してください。Webブラウザで `http://127.0.0.1:8000` を開き、起動端末に表示された **Web token** を入力します。設定ファイルの `web_token` と同じ値です。トークンはブラウザのメモリ内に保持し、localStorageやCookieに保存しません。

起動は常に `127.0.0.1:8000`、1ワーカーです。別の端末で同時にWebサーバーを起動すると `data/web.lock` により同期処理の多重起動を拒否します。stdio MCPは別プロセスで同時起動できます。

`run.sh` は `.venv/` に仮想環境を作成し、uvのキャッシュ・Pythonダウンロード先・一時ファイル・設定・DBを `data/` 配下に指定します。任意のカレントディレクトリから起動してもアプリの保存先は同じです。Pythonモジュールを直接起動した場合もアプリの設定・DBはモジュール位置から決まります。uvを別途直接操作する場合は、ホーム側へのuvキャッシュ作成を避けるため `run.sh` と同じ環境変数を指定してください。

## 設定例

実際の初回生成ファイルには、それぞれ異なるランダムトークンが入ります。以下の説明用トークンを使わず、生成されたものを保持してください。

```json
{
  "web_token": "初回生成される32文字以上のランダム値",
  "mcp_token": "Web用と異なる32文字以上のランダム値",
  "sync_interval": 60,
  "sync_batch": 100,
  "max_message_bytes": 25000000,
  "accounts": [
    {
      "id": "personal",
      "name": "個人メール",
      "email": "you@example.com",
      "enabled": true,
      "imap": {
        "host": "imap.example.com",
        "port": 993,
        "username": "you@example.com",
        "password": "APP_PASSWORD",
        "security": "tls"
      },
      "smtp": {
        "host": "smtp.example.com",
        "port": 587,
        "username": "you@example.com",
        "password": "APP_PASSWORD",
        "security": "starttls"
      },
      "folders": ["INBOX", "Sent"],
      "drafts_folder": null
    }
  ]
}
```

- 複数アカウントは `accounts` に追加します。`id` は一意かつ安定した値にしてください。
- `security` は `tls`（暗黙TLS）または `starttls`。平文認証や証明書検証無効化は実装しません。
- SMTP/IMAPパスワード認証・アプリパスワードに対応します。OAuth2専用アカウントは未対応です。
- `folders` はサーバー上の実名を指定します。存在しない `Sent` 等を推測して設定しないでください。
- `drafts_folder: null` は `\Drafts` SPECIAL-USEフラグを優先して検出します。なければ限定した既知名を使用します。曖昧・不明なら書き込みせずエラーになります。
- 自動検出できない場合は、実名を指定してください。例: `"[Gmail]/下書き"`、`"INBOX.Drafts"`。IMAPClientがmodified UTF-7を処理します。
- 下書きフォルダは自動で同期対象に追加します。フォルダの作成は行いません。
- 設定変更後はWeb／stdio両方を再起動してください。

`config.json` の認証情報と `mail.db` のメール本文は平文保存です。Linuxでは初回ディレクトリ0700、ファイル0600／umask077を使用します。既存ファイルの権限やコピー先のACLはユーザー側で確認してください。WSLのWindowsマウントではPOSIX権限の意味が異なる場合があります。バックアップは機密情報として扱ってください。

## MCP接続

### stdio

依存導入後、プロジェクトルートで次を実行できます。

```bash
.venv/bin/python -m app.mcp_server
```

要求された `python -m app.mcp_server` も、仮想環境を有効化した状態で利用できます。初回セットアップも含める場合:

```bash
bash run.sh --stdio
```

汎用MCPクライアント設定例（パスはコピー先に合わせてください）:

```json
{
  "mcpServers": {
    "portable-webmail": {
      "command": "/bin/bash",
      "args": ["/absolute/path/mcp-webmail/run.sh", "--stdio"]
    }
  }
}
```

Windows側のクライアントからWSL内へ接続する例:

```json
{
  "mcpServers": {
    "portable-webmail": {
      "command": "wsl.exe",
      "args": ["-d", "Ubuntu", "--", "bash", "/absolute/linux/path/mcp-webmail/run.sh", "--stdio"]
    }
  }
}
```

stdioはOSプロセス境界で認可され、トークンは使いません。標準出力はMCP通信用です。キャッシュを読むだけなので、最新メールを取得するにはWeb側も起動してください。

### Streamable HTTP

Web起動中の `http://127.0.0.1:8000/mcp` に接続します。末尾スラッシュ不要です。

```text
Authorization: Bearer <data/config.json の mcp_token>
Accept: application/json, text/event-stream
```

MCP SDK 1.26.0を固定しています。FastAPI親アプリのlifespanで `mcp.session_manager.run()` を管理し、SDK内の `/mcp` ルートをrootへマウントしています。通信方式は **stdio + Streamable HTTP** の2種類です。旧式の独立した `/sse` エンドポイントは実装していません。

認証ヘッダーを設定できるStreamable HTTP対応クライアントを使用してください。これはローカル固定トークン方式で、公開リモートMCP向けのOAuth認証サーバーではありません。

| Tool | 引数 | 動作 |
|---|---|---|
| list_accounts | なし | アカウント情報、ローカル未読数／総数 |
| search_emails | query, account_id?, limit=20 | 件名・送信者・本文の文字列検索（上限200） |
| get_email_detail | email_id | 本文テキストとヘッダー |
| get_thread | email_id | 同一アカウントの関連メールを時系列表示 |
| create_draft | account_id, to: string[], subject, body, reply_to_email_id? | IMAP APPENDで下書き保存 |

Resources: `mail://accounts`、`mail://emails/{email_id}`。

**send_emailツールは存在しません。** MCPとWebは別トークンを要求し、MCPトークンではREST送信APIを利用できません。メール由来のヘッダー・本文・検索結果をすべて未信頼データとしてラップし、区切りタグをエスケープします。ただしタグ付けはプロンプトインジェクションを完全に防ぐ仕組みではありません。LLMへWebトークン、設定ファイル、任意のシェル／ブラウザ操作権限も与えた場合、このMCPツール境界の外で送信できるため、OS全体の隔離は保証しません。

## Web UIと送信

1. 左側でアカウント／フォルダを選択、中央で検索・メール選択。
2. 右側でテキスト本文を確認。HTMLは明示的に切り替えて表示。
3. 新規作成／返信は下書きを保存します。宛先はカンマ区切りのメールアドレスのみです。
4. 同期後、下書きフォルダを開き、宛先（To/Cc/Bcc）・件名・本文を確認します。
5. 「確認して送信」を押して確認ダイアログを承認します。

HTMLは `iframe sandbox=""` と `srcdoc` 内へ隔離します。スクリプト・ナビゲーション要素を除去し、iframe内部のCSPで外部画像／CSS／通信をブロックします。親画面ではメールをtextContentで表示します。外部CDNのスクリプトは読み込みません。

送信時には実際の下書きフォルダ・UIDVALIDITY・本文・宛先等をIMAPから再確認します。別のメールや変更された下書きを送信しません。送信権をSQLiteへ一意に記録してからSMTP通信を開始するため、同時クリックや別ワーカーからの同じMessage-IDの再送を抑止します。

- `accepted`: SMTPサーバーが全宛先を受け付けた状態。最終配送成功とは異なります。
- `partial`: 一部宛先を拒否。成功した宛先の重複送信を避けるため自動再送しません。
- `unknown`: エラー等で結果を確定できません。サーバー上の状態を確認してください。
- `in_progress`: 送信実行中、またはプロセス停止等で結果保存前。自動再送はしません。

宛先・送信元等の検証は送信権の取得前に行います。SMTP接続・TLS・認証の失敗、およびサーバーが明示的に拒否した場合（全宛先拒否・送信者拒否・DATA拒否）は「未送信」が確定しているため送信権を解放し、原因を直した後に同じ下書きを再送できます。DATA送信中の切断・タイムアウトなど結果が確定できない場合のみ `unknown` になります。

確認画面の宛先表示と実際のSMTPエンベロープは同じ宛先パーサーで作成します（RFC 2047表示名はアドレス解析後にデコード）。送信時のSMTPポリシーでの解析結果と一致しない下書きは送信を拒否します。

SMTPとSQLiteを跨ぐ厳密なexactly-once送信は保証できません。この実装は不確実な場合に再送を止める保守的方式です。確認後に必要なら、別クライアントで状態を確認して新しい下書きを作成してください。本文内容を同じにして別Message-IDで新規作成したメールまでは重複検出しません。

送信後のDrafts削除やSentへのAPPENDは行いません。プロバイダーによるSent自動保存の有無を確認してください。送信済みの元下書きはローカル送信記録により再送不可となります。

## DB・同期

指定の `emails` カラム／UNIQUE制約に加え、`is_seen`、`references_header`、`reply_to` を持ちます。`folders` がUIDVALIDITY、`send_attempts` が送信状態を管理します。

- WAL（DBファイルに永続）とbusy_timeout=5000msを使用します。
- キャッシュ形式は `PRAGMA user_version` で管理します。メール解析方式が変わった版で起動すると、`emails`／`folders` キャッシュを破棄してIMAPから再取得します（`send_attempts` の送信記録は保持）。
- 1アカウントにつき1同期周期で1回だけIMAPログインし、全フォルダを処理します。フォルダ単位でエラーを分離し、1フォルダの失敗（存在しない・取得エラー）で他のフォルダの同期は止まりません。エラーは「認証失敗」「TLS証明書エラー」等の分類で表示し、サーバー応答文は表示しません。
- 解析中に例外を起こす壊れたメールはプレースホルダーとして保存し、以後の同期を妨げません。通信エラーはプレースホルダー化せず次周期で再試行します。
- 既読フラグは変化した行だけを書き込みます。FLAGSの取得はフォルダ全体を対象にします（CONDSTORE差分同期は未実装）。
- ネットワーク通信中はDBトランザクションを保持しません。
- フォルダ単位の短い書き込みトランザクション内でUIDVALIDITYリセット・削除反映・既読フラグ更新・新着挿入を行います。
- IMAPの読み取りはreadonly SELECTとBODY.PEEKを使用し、閲覧で既読フラグを変更しません。
- 新しいUIDから1フォルダあたり最大sync_batch件を取得します。初回大量メールの取り込みには複数同期周期が必要です。
- 件数はサーバー全体の件数ではなく、取り込み済みローカルキャッシュの件数です。
- 大きすぎるメッセージはプレースホルダーを保存して、過大メールによる取り込み停止を避けます。`max_message_bytes` を引き上げると、それ以前の上限で保存したプレースホルダーは次の同期で自動的に再取得されます。
- 日本語: ISO-2022-JPのNEC特殊文字（①、㈱など、Outlook等のCP50220相当）、半角カナ、生8bitヘッダー（Shift_JIS等）、charset未指定のEUC-JP、iso-8859-1と誤宣言されたShift_JISを復号します。
- スレッドはMessage-ID／In-Reply-To／Referencesを辿り、同一アカウント内で最大500件。ヘッダーがない場合や未同期メールは追跡できません。
- 検索はLIKEのリテラル部分一致で、SQLはパラメータ化。大規模メールボックス向け全文索引は未実装です。

WALのためDBはローカルファイルシステムへ置いてください。NFS／SMB等での動作は想定しません。WSL2では `/mnt/c` などWindowsドライブ（DrvFs／9P）上ではSQLite WALの共有メモリとファイルロックが不安定になり得るため、`~/` などLinux側へコピーして実行してください。`run.sh` は `/mnt/<ドライブ>/` 配下での起動時に警告を表示します。Webサーバーを二重起動した場合は `data/web.lock` を示すエラーで停止します。

## 移行・バックアップ

1. Webプロセスと全stdio MCPプロセスを停止します。
2. プロジェクト全体、または `data/` 全体をコピーします。`mail.db-wal` / `mail.db-shm` が残っていれば同時に含め、`mail.db` だけを稼働中にコピーしないでください。
3. 移行先で `bash run.sh` を実行します。場所が変わると生成物 `.venv` を作り直します。Python環境の再構築に初回ネットワーク接続が必要な場合があります。
4. MCPクライアントの外部設定に書かれた起動パスを更新します。

アカウント・メール・送信履歴は `data/` に完結します。`data/uv-cache` 等のキャッシュは停止中に省略できますが、`config.json`、`mail.db`関連ファイルは保持してください。Windows仮想環境をLinuxへそのまま流用する方式ではありません。

## 検証

```bash
bash run.sh --test
```

テストは実アカウントへ接続・送信しません。SQLite複数プロセスアクセス、日本語MIME、UIDVALIDITY変更、下書きAPPEND、Bcc除去、SMTP部分拒否／結果不明時の再送防止、Web認証・Origin・Host、実stdioサブプロセスとHTTP MCP通信を検証します。

開発時の実行結果と制約は `VALIDATION.md` を参照してください。

## 初版の範囲

- 添付ファイルの有無を検出しますが、アップロード／ダウンロード／内容確認のUIはありません。添付付き下書きはWeb／RESTとも送信を拒否します。
- 下書き編集・削除、メール削除・移動、既読変更、OAuth2、IDLE常時接続、CONDSTORE差分同期、全文索引は未実装です。DBの過去版はキャッシュ再構築で移行します。
- 送信元は設定アカウントのアドレスに限定し、Resentヘッダーと重複宛先ヘッダーを拒否します。国際化ローカルパートを持つ宛先（SMTPUTF8）は対象外です。
- サーバー切断時のAPPEND結果が不明な場合も自動再試行しません。下書きが存在するか先に確認してください。

## 実装参照

MCPの親ASGIアプリでのlifespan管理は[公式SDKのASGI統合資料](https://py.sdk.modelcontextprotocol.io/run/asgi/)を確認し、実装APIは固定した[SDK v1.26.0 FastMCPソース](https://github.com/modelcontextprotocol/python-sdk/blob/v1.26.0/src/mcp/server/fastmcp/server.py)に合わせています。
