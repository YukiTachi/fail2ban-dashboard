# Fail2ban Dashboard

Fail2banの管理ダッシュボード - BANしたIPの管理を簡単に

## 機能

- **レスポンシブデザイン**: PC・スマホ両対応
- **Jail一覧表示**: グループごとにカード表示
  - Currently Failed: 現在失敗回数をカウント中のIP数
  - Total Failed: 累計失敗数
  - Currently Banned: 現在BANしているIP数
  - Total Banned: 累計BAN数
- **詳細設定画面**:
  - (A) 失敗回数をカウント中のIPをBANするかどうかの設定
  - (B) 現在BANしているIP（Reject回数が多い上位30個）と国の情報
  - (C) Reject回数のヒストグラム表示
- **認証機能**: ログインが必要
- **国情報表示**: IPアドレスから国を自動取得
- **色分け表示**: Jailごとに異なる色で表示

## スクリーンショット

```
+------------------+------------------+------------------+
|      sshd        |   postfix-sasl   |     nginx        |
|   (青色カード)    |   (緑色カード)    |  (オレンジカード)  |
|                  |                  |                  |
| Failed: 5        | Failed: 12       | Failed: 3        |
| Banned: 128      | Banned: 45       | Banned: 22       |
+------------------+------------------+------------------+
```

## 必要要件

- Python 3.8+
- Fail2ban
- sudo権限（fail2ban-client実行用）

## クイックスタート

最小限の手順で起動する方法：

```bash
# 1. クローン
git clone https://github.com/yourusername/fail2ban-dashboard.git
cd fail2ban-dashboard

# 2. セットアップ
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. 設定（パスワードを変更）
cp .env.example .env
nano .env  # ADMIN_PASSWORD を変更

# 4. 起動
cd backend
python app.py
```

ブラウザで http://localhost:5000 にアクセス（デフォルト: admin / admin）

## インストール

```bash
# リポジトリをクローン
git clone https://github.com/yourusername/fail2ban-dashboard.git
cd fail2ban-dashboard

# 仮想環境を作成
python3 -m venv venv
source venv/bin/activate

# 依存パッケージをインストール
pip install -r requirements.txt

# 設定ファイルをコピー
cp .env.example .env

# .envファイルを編集してパスワードを変更
nano .env
```

## 設定

`.env`ファイルを編集:

```bash
# Flask secret key (本番環境では必ず変更！)
SECRET_KEY=your-secret-key-change-this-in-production

# 管理者認証情報
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password

# サーバー設定
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
```

## sudoers設定

パスワードなしでコマンドを実行するには:

```bash
sudo visudo
```

以下を追加:
```
# Webサーバーの実行ユーザーに応じて変更（www-data, httpd, nginx等）
www-data ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
www-data ALL=(ALL) NOPASSWD: /usr/sbin/iptables-save -c
www-data ALL=(ALL) NOPASSWD: /usr/bin/tail
www-data ALL=(ALL) NOPASSWD: /usr/bin/grep
www-data ALL=(ALL) NOPASSWD: /usr/bin/test
```

> **Note**: 実行ユーザーは環境によって異なります
> - Debian/Ubuntu: `www-data`
> - RHEL/CentOS: `apache` または `nginx`
> - KUSANAGI: `httpd`
>
> 確認方法: `ps aux | grep nginx` または `ps aux | grep apache`

## 起動

### 開発モード

```bash
cd backend
python app.py
```

### 本番環境（systemd）

`/etc/systemd/system/fail2ban-dashboard.service`:

```ini
[Unit]
Description=Fail2ban Dashboard
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/fail2ban-dashboard/backend
Environment="PATH=/path/to/fail2ban-dashboard/venv/bin"
ExecStart=/path/to/fail2ban-dashboard/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable fail2ban-dashboard
sudo systemctl start fail2ban-dashboard
```

## アクセス

ブラウザで以下にアクセス:
- http://localhost:5000
- http://your-server-ip:5000

## API エンドポイント

| エンドポイント | メソッド | 説明 |
|--------------|---------|------|
| `/api/jails` | GET | 全Jailの一覧と状態を取得 |
| `/api/jail/<name>` | GET | 特定Jailの詳細情報を取得 |
| `/api/jail/<name>/histogram` | GET | Reject数のヒストグラムデータを取得 |
| `/api/jail/<name>/ban` | POST | IPをBANする |
| `/api/jail/<name>/unban` | POST | IPのBANを解除する |
| `/api/logs/<name>` | GET | ログからの攻撃情報を取得 |

## ディレクトリ構成

```
fail2ban-dashboard/
├── backend/
│   ├── app.py              # Flask メインアプリ
│   ├── fail2ban_service.py # fail2ban連携
│   ├── geoip_service.py    # 国情報取得
│   └── log_parser.py       # ログ解析
├── frontend/
│   ├── css/
│   └── js/
├── templates/
│   ├── index.html          # ダッシュボード
│   ├── detail.html         # 詳細画面
│   └── login.html          # ログイン画面
├── .env.example
├── requirements.txt
└── README.md
```

## セキュリティ注意事項

- `.env`ファイルのパスワードは必ず変更してください
- 本番環境ではHTTPSを使用してください（nginx等でリバースプロキシ）
- ファイアウォールでアクセスを制限してください

## ライセンス

MIT License
