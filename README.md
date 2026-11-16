# MCP Webmail — Linux / WSL2 用ポータブルWebメール

Python 3.11以上と `uv` で動作する、ローカル専用のメールクライアント（Web UI）兼 MCPサーバーです。

**v0.3** で、一般的なメールクライアントとして使える機能と、対応サービスを広げました。

- Gmail / iCloud / Microsoft 365・Outlook.com のプリセット、IMAPに加えて **POP3受信**
- アプリパスワードと **OAuth2**（Google / Microsoft）の両対応
- フォルダ自動検出、既読・スター・移動・アーカイブ・削除、添付の表示と送信、Cc/Bcc、全員に返信、転送、下書き編集、作成画面からの送信、送信済みへの保存
- **スマートフォン向けレイアウト**と、Tailscale / Cloudflare Tunnel 経由の利用
- AI（MCP）に許可する操作を **3段階から選択**

既存環境の更新は [UPGRADE_V0_3.md](UPGRADE_V0_3.md)、テスト結果と未検証の範囲は [VALIDATION.md](VALIDATION.md) を参照してください。

## 構成

```text
mcp-webmail/
├── app/
│   ├── config.py            # 設定モデル
│   ├── account_settings.py  # アカウント管理・暗号化
│   ├── providers.py         # サービス別プリセット、OAuthエンドポイント
│   ├── oauth.py             # OAuth2（PKCE）とXOAUTH2トークン
│   ├── db.py                # SQLiteキャッシュ
│   ├── mail_parser.py       # MIME解析・添付
│   ├── imap_sync.py         # IMAP/POP3の同期とサーバー操作
│   ├── mailbox.py           # 既読・移動・削除・添付（Web/MCP共通）
│   ├── smtp_client.py       # 作成・下書き・送信
│   ├── mcp_server.py        # MCPツール（権限レベル別）
│   └── main.py              # Web API
├── static/                  # index.html / app.css / app.js
├── tests/
├── data/                    # 初回起動でconfig.json/mail.db等を生成
├── pyproject.toml / uv.lock
└── run.sh
```

## 起動

LinuxまたはWSL2のLinuxファイルシステム上へ展開してください（WSLでは `/mnt/c` ではなく `~/` 配下）。前提は Python 3.11以上、`uv`、Bash、信頼済みCA証明書です。

```bash
cd mcp-webmail
bash run.sh
```

1. ブラウザで `http://127.0.0.1:8000` を開き、起動端末に表示された **Web token** を入力します。
2. 初回は設定画面が開きます。**マスターパスワード**（12文字以上）と、**AI（MCP）に許可する操作**を選びます。
3. 「メールサービス」を選ぶとサーバー名が入力されます。メールアドレスとパスワード等を入れて保存し、「接続テスト」で確認します。

サーバーを再起動するとロック状態に戻ります。起動後に一度、マスターパスワードを入力してください。

起動は常に `127.0.0.1:8000`、1ワーカーです。アプリのデータ・uvのキャッシュ・仮想環境はすべてプロジェクト配下に置き、ホームディレクトリへは書き込みません。Webサーバーの二重起動は `data/web.lock` で拒否します。

## 対応サービス

| サービス | 受信 | 認証 | 備考 |
|---|---|---|---|
| Gmail / Google Workspace | IMAP | アプリパスワード または OAuth2 | 送信済みはGmailが自動保存 |
| iCloudメール | IMAP | アプリ用パスワード | 通常のApple Accountパスワードは不可 |
| Microsoft 365（Exchange Online） | IMAP | OAuth2 | 管理者によるIMAP・SMTP AUTHの許可が必要 |
| Outlook.com / Hotmail | IMAP | OAuth2 | テナントは `consumers` |
| その他 | IMAP | パスワード | サーバー名を手入力 |
| POP3 | POP3 | パスワード | 下記参照 |

- 接続は TLS または STARTTLS のみです。平文認証と証明書検証の無効化は実装していません。
- **Exchange** は Exchange Online を IMAP/SMTP + OAuth2 で利用する方式です。オンプレミスのExchange（EWS）と、Microsoft Graph API には対応していません。
- **POP3** は受信トレイだけを取得し、**サーバー上のメールは削除しません**。下書き・送信済み・ごみ箱・アーカイブと、既読・スターの状態はこのPC内だけに保存されます（他の端末とは同期されません）。

### OAuth2の設定

OAuth2を使うには、ご自身のアカウントでアプリ（OAuthクライアント）を登録し、クライアントIDを設定画面に入力します。

1. アプリを登録し、リダイレクトURIに `http://localhost:8000/oauth/callback` を指定します。
   - **Google**: Google Cloud コンソールでGmail APIを有効化し、OAuthクライアント（種類: デスクトップアプリ）を作成。クライアントIDとシークレットを入力します。スコープは `https://mail.google.com/` です。
   - **Microsoft**: Microsoft Entra 管理センターでアプリを登録し、「モバイルとデスクトップ アプリケーション」のリダイレクトURIに上記を追加。APIのアクセス許可に `IMAP.AccessAsUser.All` `SMTP.Send` `offline_access` を追加します。シークレットは不要です。
2. 設定画面で認証方式を「OAuth2」にして保存し、「サインイン」→「サインインページを開く」で認証します。
3. 完了すると自動で同期が始まります。

サインインは**サーバーを動かしているPC上のブラウザ**で行ってください（リダイレクト先がlocalhostのため）。リフレッシュトークンは暗号化して `data/config.json` に保存し、アクセストークンはメモリ内だけに保持します。

## スマートフォン・外出先からの利用

画面幅800px以下では、フォルダ一覧（ドロワー）・メール一覧・本文を1画面ずつ切り替えるレイアウトになります。ログイン画面の「この端末に記憶する」をオンにすると、Webトークンをそのブラウザに保存します（共有端末では使わないでください）。

サーバーは `127.0.0.1` でしか待ち受けません。別の端末から使うときは、同じPC上の中継ソフトから転送します。

1. 設定画面の「外部からアクセスするホスト名」に、アクセスに使う名前を登録します（例: `pc.tailnet-name.ts.net`）。登録していない名前でのアクセスは拒否します。
2. 中継を起動します。
   - Tailscale: `tailscale serve --bg 8000`
   - Cloudflare Tunnel: `cloudflared tunnel --url http://127.0.0.1:8000`（または名前付きトンネル）

- **Tailscale** は自分の端末だけが届くため、こちらを推奨します。
- **Cloudflare Tunnel** はインターネットに公開されます。必ず Cloudflare Access などの前段認証を併用してください。Webトークンは推測できない長さですが、漏れた場合はメールの閲覧・送信・削除がすべて可能になります。
- MCPのHTTP接続（`/mcp`）は、引き続きローカル（127.0.0.1 / localhost）からのみ利用できます。

## MCP接続

### 許可する操作（権限レベル）

初回設定または設定画面の「全般」で選びます。MCP側からは変更できません。

| レベル | 使えるツール |
|---|---|
| 閲覧と下書きのみ（既定） | `list_accounts` `search_emails` `get_email_detail` `get_thread` `create_draft` |
| ＋整理 | 上記 ＋ `mark_emails`（既読・スター） `move_emails` `archive_emails` |
| ＋送信・削除 | 上記 ＋ `delete_emails` `send_draft` |

- 権限を**広げた**ときは、Webサーバーとstdio MCPを再起動すると新しいツールが現れます。**狭めた**ときは即時に効きます。
- `send_draft` は既存の下書きを1回だけ送信します。`delete_emails` は既定でごみ箱へ移動します。
- メール本文は未信頼データとしてタグで囲んで返しますが、プロンプトインジェクションを完全には防げません。「送信・削除」を許可すると、メールに仕込まれた指示でAIが誤操作するリスクが上がります。必要なときだけ有効にしてください。

Resources: `mail://accounts`、`mail://emails/{email_id}`。

### stdio

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

Windows側のクライアントからWSLへ接続する場合は `"command": "wsl.exe"`、`"args": ["-d", "Ubuntu", "--", "bash", "/absolute/linux/path/mcp-webmail/run.sh", "--stdio"]` とします。

stdioはキャッシュを読むため、最新のメールを取得するにはWeb側も起動しておきます。下書き保存や整理・送信などサーバーへ接続する操作には、環境変数 `WEBMAIL_MASTER_PASSWORD` でのロック解除が必要です。

### Streamable HTTP

Web起動中の `http://127.0.0.1:8000/mcp` に接続します。

```text
Authorization: Bearer <data/config.json の mcp_token>
Accept: application/json, text/event-stream
```

MCP SDK 1.26.0固定、通信方式は stdio と Streamable HTTP の2種類です。WebトークンとMCPトークンは別で、MCPトークンではWeb APIや設定を操作できません。

## Web UIの機能

- **一覧**: 検索（件名・差出人・宛先・本文）、未読／スター／添付での絞り込み、複数選択での一括操作。
- **閲覧**: テキスト表示が既定。HTML表示は隔離したiframe内で行い、スクリプトと外部画像・外部通信を遮断します（メールに添付された画像は表示）。開いたメールは既読にします（設定でオフにできます）。
- **添付**: ダウンロードのみ。ブラウザ内では開きません。
- **作成**: 宛先・Cc・Bcc、添付、署名、返信・全員に返信・転送。下書きは保存後に編集できます。
- **送信**: 作成画面の「送信」、または下書きを開いて「確認して送信」。どちらも宛先の確認ダイアログを経ます。
- **整理**: 既読／未読、スター、アーカイブ、フォルダ移動、削除（ごみ箱へ。ごみ箱内では完全削除）。

### 送信の安全策

- 下書きから送る場合は、送信直前にサーバー上の下書きを再取得し、表示した内容（宛先・本文・添付）と一致するときだけ送信します。
- 送信権をMessage-ID単位でSQLiteに記録してからSMTP通信を始めるため、二重クリックや再実行で同じメールを重複送信しません。
- 結果は `accepted`（全宛先を受付）、`partial`（一部拒否）、`unknown`（結果を確定できない）のいずれかです。接続・認証の失敗やサーバーの明示的な拒否は「未送信」と確定できるため再送できますが、`unknown` の場合は自動再送しません。サーバーの送信済みを確認してください。
- 送信後は送信済みフォルダへ保存し、元の下書きを削除します（GmailとMicrosoftはサーバーが自動保存するため保存を省略）。これらに失敗しても送信結果は変わらず、画面に警告を表示します。
- 送信元は設定したアカウントのアドレスに限定します。

## データ・同期

- メールは `data/mail.db`（SQLite、WAL）にキャッシュします。件数はサーバー全体ではなく取り込み済みの件数です。
- IMAPは1周期につき1アカウント1回ログインし、フォルダ単位でエラーを分離します。新しいメールから1フォルダあたり最大 `sync_batch` 件ずつ取り込みます。
- 「サーバーの全フォルダを同期」では、選択できないフォルダと、全メールが重複するGmailの「すべてのメール」を除いて同期します。
- 下書き・送信済み・ごみ箱・アーカイブ・迷惑メールは、SPECIAL-USE属性、次に一意に決まる既知の名前で判定します。判定できない場合は設定画面で指定できます。
- 既読・移動・削除はサーバーを先に変更してからキャッシュへ反映します。UIDVALIDITYが変わっていた場合は操作を中止します。
- 暗号化されるのはメールパスワードとOAuthトークンだけです。`mail.db` の本文、メールアドレス、Web/MCPトークンは暗号化されません。`data/` は0700、ファイルは0600で作成します。バックアップは機密情報として扱ってください。
- 日本語: ISO-2022-JP（NEC特殊文字を含む）、Shift_JIS、EUC-JP、誤ったcharset宣言を復号します。
- WALのためDBはローカルファイルシステムに置いてください。NFS／SMB、WSLの `/mnt/c` は非対応です。

## 移行・バックアップ

1. Webプロセスと全stdio MCPプロセスを停止します。
2. プロジェクト全体、または `data/` 全体をコピーします（`mail.db-wal` / `mail.db-shm` も一緒に）。
3. 移行先で `bash run.sh` を実行します。場所が変わると `.venv` を作り直します。
4. MCPクライアント設定の起動パスを更新します。

## 検証

```bash
bash run.sh --test
```

テストは実アカウントへ接続・送信しません。詳細は [VALIDATION.md](VALIDATION.md) を参照してください。

## 未対応・制約

- オンプレミスExchange（EWS）、Microsoft Graph、POP3でのOAuth2。
- HTMLメールの作成、アドレス帳・宛先の入力補完、振り分けルール、複数の差出人アドレス。
- IDLEによる即時受信とCONDSTORE差分同期（`sync_interval` 秒ごとの定期同期です）。全文検索は部分一致のため、大量のメールでは遅くなります。
- フォルダの作成・名前変更・削除。
- 国際化ローカルパートを持つ宛先（SMTPUTF8）。
- 送信結果が `unknown` になったメールの自動再送、送信済み保存の再試行。
