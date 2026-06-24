# 🔍 proxenum —  自動列挙スイート

> **scan · focus · drill · stax**

---

## 📖 概要

**proxenum** は 実環境のペネトレーションテストに特化した Python 製の自動列挙スイートです。  
ターゲットの列挙から脆弱性スキャン、認証情報クラッキング、静的解析まで、一連の偵察作業を 4 つのモードでカバーします。

| モード | 用途 | 主な対象 |
|--------|------|---------|
| `scan` | マルチホスト一括列挙 | SMB + Nmap + パスワードスプレー |
| `focus` | 単一 IP の深堀り | 全ポート + サービス別詳細列挙 |
| `drill` | 自動スコアリング + 深堀り | 複数ホスト → トップ N を自動 focus |
| `stax` | 静的解析ユーティリティ | ハッシュクラック・ログ解析・ファイル操作 |

起動時にランダムな名言（英語 + 日本語訳）が表示されます。ちょっとした心の余裕を。

---

## 🛠️ インストール・依存ツール

### Python 依存ライブラリ

```bash
pip install -r requirements.txt
# 必要なのは rich>=13.0.0 のみ
```

### 外部ツール

以下のツールがシステムにインストールされている必要があります。  
未インストールのツールは自動的にスキップされます（エラーにはなりません）。

| ツール | 用途 | インストール例 |
|--------|------|--------------|
| `nmap` | ポートスキャン・脆弱性検出 | `apt install nmap` |
| `rustscan` | 高速非同期ポート発見 | [rustscan releases](https://github.com/RustScan/RustScan) |
| `nxc` / `netexec` | SMB/WinRM/LDAP/FTP 列挙 | `pipx install netexec` |
| `feroxbuster` | Web コンテンツ探索（ディレクトリブルート） | `apt install feroxbuster` |
| `ffuf` | vhost ファジング | `apt install ffuf` |
| `hashcat` | NTLM ハッシュクラッキング | `apt install hashcat` |
| `whatweb` | Web 技術フィンガープリント | `apt install whatweb` |
| `searchsploit` | Exploit DB 検索 | `apt install exploitdb` |
| `davtest` | WebDAV 検出・テスト | `apt install davtest` |
| `enum4linux-ng` | SMB/LDAP 詳細列挙 | `apt install enum4linux-ng` |
| `ldapsearch` | LDAP クエリ | `apt install ldap-utils` |
| `smbclient` | SMB 共有接続 | `apt install smbclient` |
| `xsltproc` | Nmap XML → HTML 変換 | `apt install xsltproc` |
| `impacket` | AS-REP/Kerberoast ツール群 | `pipx install impacket` |
| `redis-cli` | Redis 列挙 | `apt install redis-tools` |

### ワードリスト（推奨）

```bash
# SecLists（feroxbuster / ffuf 用）
apt install seclists
# rockyou.txt（hashcat 用）
gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

## 🚀 基本的な使い方

```bash
python3 proxenum.py <mode> [options]
# または
chmod +x proxenum.py
./proxenum.py <mode> [options]
```

---

## 🟢 scan モード

マルチホスト対応の一括列挙モードです。指定した IP リスト（またはサブネット）に対して、SMB 列挙 → ポートスキャン → パスワードスプレー → 追加列挙を順次実行します。

### 実行フロー

```
┌─────────────────────────────────────────────────────┐
│ 1. nxc smb — SMB 情報収集（hostname / domain / signing）
│ 2. rustscan → nmap -p- → nmap -sCV（全 TCP ポート）
│ 3. nxc smb / winrm — パスワードスプレー（任意）
│ 4. 匿名 SMB 共有 / LDAP 列挙・AS-REP ロースト（任意）
│ 5. 認証済み SMB・LDAP 列挙 + Kerberoast（クレデンシャル取得後）
│ 6. scan_N.html レポート生成
└─────────────────────────────────────────────────────┘
```

### オプション一覧

| オプション | 説明 |
|-----------|------|
| `-i IP/FILE` | ターゲット IP（単一 IP、CIDR、またはファイルパス） **必須** |
| `-u USER/FILE` | ユーザー名（単一またはファイル） |
| `-p PASS/FILE` | パスワード（`-u` と同時指定が必要） |
| `-n HASH/FILE` | NTLM ハッシュ（`-u` と同時指定が必要） |
| `--proxy` | proxychains4 -q を通じて全コマンドを実行（SOCKS ピボット） |
| `--ligolo` | ligolo-ng TUN インターフェース経由（保守的タイミング） |
| `--top-ports N` | 高速モード：上位 N ポートのみスキャン（rustscan / -p- をスキップ） |
| `--no-portscan` | ポートスキャンをスキップ |
| `--no-report` | HTML レポートを生成しない（CLI 出力のみ） |
| `--new-log` | 新しい proxscan ログを強制作成 |
| `--skip-log` | proxscan ログの読み書きを完全にスキップ |
| `--no-brute` | nxc の --no-brute（ユーザー:パスワードを 1:1 ペアリング） |
| `--continue-on-success` | 認証成功後もスプレーを継続 |
| `--local-auth` | nxc --local-auth を使用 |

### 使用例

```bash
# 基本的なスキャン（IPファイル + ユーザー + パスワード）
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt

# SOCKS プロキシ経由（chisel / proxychains 使用時）
python3 proxenum.py scan -i ip.txt --proxy

# ligolo-ng トンネル経由
python3 proxenum.py scan -i ip.txt --ligolo

# 高速モード：上位 100 ポートのみ
python3 proxenum.py scan -i ip.txt --top-ports 100

# NTLM ハッシュでスプレー
python3 proxenum.py scan -i ip.txt -u users.txt -n hashes.txt

# 単一 IP、レポートなし
python3 proxenum.py scan -i 10.10.10.5 --no-report

# ログファイルからポート情報を再利用（再スキャン不要）
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt
# → proxscan.1.json が存在すれば自動的に読み込み、ポートスキャンをスキップ

# 新しいログとして強制保存
python3 proxenum.py scan -i ip.txt --new-log
```

### プロキシ vs ligolo の違い

| 機能 | `--proxy` | `--ligolo` |
|------|----------|-----------|
| 接続方式 | proxychains4 -q 経由 | TUN インターフェース直接 |
| SYN スキャン | 不可（-sT のみ） | 可能 |
| rustscan | スキップ | 使用（低速設定） |
| フルスキャン | top-30 ポートのみ | 全ポート（低速レート） |
| 対象 | chisel SOCKS ピボット | ligolo-ng セットアップ済み |

---

## 🟡 focus モード

単一 IP に対する深堀り列挙モードです。rustscan + nmap -p- を並列実行し、開いたポートに応じてサービス別の詳細列挙を自動ディスパッチします。

### 実行フロー

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SMB プレチェック（hostname / domain 取得）
│ 2. rustscan + nmap -p- 並列実行 → 全 TCP ポート発見
│ 3. nmap -sCV（バージョン + スクリプト検出）
│ 4. nmap --script vuln（脆弱性スキャン）
│ 5. nmap -sU --top-ports 20（UDP スキャン）
│ 6. ポート別自動列挙:
│    SMB(445)  → nxc shares/users + enum4linux-ng
│    HTTP(80/443/8080/8443) → whatweb + curl + feroxbuster + davtest + ffuf vhost
│    LDAP(389/636) → nxc ldap + ldapsearch
│    FTP(21)   → nxc ftp anonymous
│    SSH(22)   → SSH バナー取得
│    MSSQL(1433) → nxc mssql + SA 試行
│    MySQL(3306) → nxc mysql
│    PostgreSQL(5432) → nxc postgres
│    Redis(6379) → redis-cli ping/info
│    SMTP(25)  → nxc smtp
│ 7. focus.html レポート生成
└─────────────────────────────────────────────────────────────┘
```

### オプション一覧

| オプション | 説明 |
|-----------|------|
| `-i IP` | ターゲット IP アドレス **必須** |
| `--ligolo` | ligolo-ng TUN インターフェース経由 |
| `--top-ports N` | 高速モード：上位 N ポートのみスキャン |
| `--web-exts EXTS` | feroxbuster に渡す拡張子（例：`php,html,asp`） |
| `--fw` | feroxbuster フィルター：ワード数 |
| `--fl` | feroxbuster フィルター：行数 |
| `--fs` | feroxbuster フィルター：サイズ |
| `--no-report` | HTML レポートを生成しない |

### 使用例

```bash
# 基本的な深堀りスキャン
python3 proxenum.py focus -i 10.10.10.5

# PHP + HTML 拡張子を feroxbuster に追加
python3 proxenum.py focus -i 10.10.10.5 --web-exts php,html

# 高速モード（上位 200 ポート）
python3 proxenum.py focus -i 10.10.10.5 --top-ports 200

# ligolo 経由で ASP.NET サイトを列挙
python3 proxenum.py focus -i 172.16.100.10 --ligolo --web-exts asp,aspx
```

---

## 🟣 drill モード

複数ターゲットをスキャンしたあと、スコアリングアルゴリズムで最も価値の高いホストを自動選択し、focus 処理を連続実行するモードです。

### スコアリングロジック

各ホストは開いているポートの組み合わせによってポイントが付与されます：

| ポート/組み合わせ | ポイント | 理由 |
|-----------------|---------|------|
| MSSQL (1433) | 18 | 高価値 DB |
| WinRM (5985/5986) | 14 | Windows フットホールド |
| Redis (6379) | 14 + 8 | 無認証アクセス多数 |
| MongoDB (27017) | 14 + 8 | 無認証アクセス多数 |
| SMB (445) | 12 | リレー候補・共有アクセス |
| DC コンボ (88+389+445) | ボーナス +12 | ドメインコントローラー |
| MSSQL+SMB | ボーナス +10 | 高価値 |
| WinRM+SMB | ボーナス +6 | 完全な Windows フットホールド |

### オプション一覧

| オプション | 説明 |
|-----------|------|
| `-i FILE` | ターゲット IP リストファイル **必須** |
| `--top N` | 深堀りする上位ターゲット数（デフォルト：3） |
| `--ligolo` | ligolo-ng TUN インターフェース経由 |
| `--top-ports N` | 高速モード：上位 N ポートのみスキャン |
| `--web-exts EXTS` | feroxbuster 拡張子指定 |
| `--no-report` | HTML レポートを生成しない |

### 使用例

```bash
# 全ホストスキャン後、上位 3 つを深堀り
python3 proxenum.py drill -i ip.txt

# 上位 5 ホストを深堀り
python3 proxenum.py drill -i ip.txt --top 5

# 高速モード + ASP.NET 拡張子
python3 proxenum.py drill -i ip.txt --top 3 --top-ports 200 --web-exts asp,aspx

# ligolo 経由
python3 proxenum.py drill -i ip.txt --ligolo --top 5
```

---

## ⚙️ stax モード

静的解析・ユーティリティモードです。スキャン不要で、取得済みのハッシュファイルやダンプファイルを解析します。

### サブ機能一覧

| オプション | 説明 |
|-----------|------|
| `--crack-ntlm FILE` | NTLM ハッシュを hashcat + rockyou.txt でクラック |
| `--crack-secrets FILE` | impacket secretsdump 出力を解析し NT ハッシュを抽出・クラック |
| `--mimi-check FILE` | Mimikatz / pypykatz ダンプを解析（平文パスワード + NTLM 一覧化） |
| `--winpeas-check FILE` | WinPEAS 出力から権限昇格の手掛かりを抽出 |
| `--linpeas-check FILE` | LinPEAS 出力から権限昇格の手掛かりを抽出 |
| `--merge-file FILE...` | 複数ファイルを統合・重複排除（`-o` で出力先を指定） |
| `--push-file SOURCE` | SOURCE の新規エントリを TARGET（`-o`）に追記・重複排除 |
| `--parse-users` | コマンド履歴からユーザー名を自動収集 |
| `--parse-web` | フェロックスバスターや Web 列挙結果を解析 |
| `-o FILE` | `--merge-file` / `--push-file` の出力先ファイル |
| `--show-logs` | カレントディレクトリの proxscan ログ一覧を表示 |

### 使用例

```bash
# NTLM ハッシュをクラック
python3 proxenum.py stax --crack-ntlm ntlm_hashes.txt

# secretsdump 出力を解析してクラック
python3 proxenum.py stax --crack-secrets secretsdump_output.txt

# Mimikatz ダンプ解析（平文パスワード + ハッシュを分離して表示）
python3 proxenum.py stax --mimi-check mimikatz.txt
# → mimi_users.txt と mimi_ntlm.hash を自動エクスポート

# WinPEAS 解析（AlwaysInstallElevated, トークン特権, 書き込み可能サービスなど）
python3 proxenum.py stax --winpeas-check winpeas_output.txt

# LinPEAS 解析（SUID バイナリ, sudo NOPASSWD, NFS no_root_squash など）
python3 proxenum.py stax --linpeas-check linpeas_output.txt

# 複数のユーザーリストを統合・重複排除
python3 proxenum.py stax --merge-file users1.txt users2.txt users3.txt -o all_users.txt

# 新しいユーザーを既存リストに追記（重複なし）
python3 proxenum.py stax --push-file new_users.txt -o all_users.txt

# proxscan ログ一覧を確認
python3 proxenum.py stax --show-logs
```

#### --mimi-check が対応するフォーマット

| フォーマット | 対応 |
|------------|------|
| pypykatz 出力（`== LogonSession ==`） | ✅ |
| 古典的 Mimikatz（`sekurlsa::logonpasswords`） | ✅ |
| lsadump::sam（`User :` / `Hash NTLM:`） | ✅ |
| lsadump::dcsync（`SAM Username :` / `Credentials:`） | ✅ |

#### --winpeas-check が検出する項目

| カテゴリ | 内容 |
|---------|------|
| AlwaysInstallElevated | MSI インストーラーが SYSTEM で動作 |
| Token Privilege | SeImpersonatePrivilege 等（Potato 攻撃）|
| Unquoted Service Path | 引用符なしサービスパス |
| Writable Service | 書き込み可能なサービスバイナリ |
| Autologon | レジストリの平文クレデンシャル |
| LAPS | LAPS 管理パスワードの読み取り |
| Scheduled Task | 書き込み可能なタスクターゲット |
| Stored Credential | Windows 資格情報ボールト |
| PATH Hijack | 書き込み可能な PATH ディレクトリ |
| Password in Registry | レジストリの平文パスワード |

#### --linpeas-check が検出する項目

| カテゴリ | 内容 |
|---------|------|
| Sudo NOPASSWD | パスワードなしの sudo |
| NFS no_root_squash | root squash 無効の NFS |
| Writable Sensitive File | /etc/passwd 等の world-writable |
| Capability | cap_setuid+ep 等の Linux capability |
| Cron Writable | 書き込み可能な cron ジョブ |
| SSH Private Key | SSH 秘密鍵の発見 |
| SUID Binary | GTFOBins 対象の SUID バイナリ |
| Docker/LXC Socket | コンテナエスケープ |

---

## 📋 proxscan スキャンログ機能

`scan` モードは実行後に `proxscan.N.json` という名前のログファイルを自動保存します。

### 動作

```
初回実行: proxscan.1.json を作成
2回目実行: proxscan.1.json を自動読み込み → ポートスキャンをスキップして SMB 列挙・スプレーに進む
--new-log: proxscan.2.json を新規作成（既存ログは無視）
--skip-log: ログの読み書きを完全にスキップ
```

### ログの内容

```json
{
  "created": "2025-05-25T10:30:00.000000",
  "version": "1.5.0",
  "domain": "medtech.com",
  "hosts": {
    "10.10.10.5": {
      "hostname": "DC01",
      "fqdn": "dc01.medtech.com",
      "domain": "medtech.com",
      "os_info": "Windows Server 2022",
      "smb_signing": true,
      "smbv1": false,
      "open_ports": {"445": "microsoft-ds", "88": "kerberos-sec"},
      "udp_ports": {}
    }
  }
}
```

### ログ管理

```bash
# 現在のログ一覧を表示
python3 proxenum.py stax --show-logs

# 出力例:
# File              Created              Domain       Hosts  Version
# proxscan.1.json   2025-05-25 10:30:00  medtech.com  7      1.5.0
# proxscan.2.json   2025-05-25 14:15:00  corp.local   3      1.5.0
```

---

## 📊 HTML レポート

スキャン結果は自動的にインタラクティブな HTML ファイルに出力されます。

| ファイル名 | 生成モード | 内容 |
|-----------|-----------|------|
| `scan_N.html` | scan（N=ターゲット数） | マルチホスト全体サマリー |
| `drill_N.html` | drill（N=ターゲット数） | ドリル結果 + 各 focus セクション |
| `focus.html` | focus | 単一ホスト詳細レポート |

### レポートの主なセクション

**scan / drill レポート（サイドバーナビゲーション）**

| タブ | 内容 |
|-----|------|
| Overview | ホスト数・ポート数・クレデンシャル数・経過時間 |
| Critical | SMB 共有アクセス / Vuln 発見 / 匿名アクセス / ユーザー列挙 |
| Hosts | IP・ホスト名・FQDN・OS・ドメイン・SMB Signing テーブル |
| Ports | ポートヒートマップ（カテゴリ別カラーコード）+ 全ポートチップ |
| Credentials | 認証成功クレデンシャル一覧（Admin 判定付き） |
| Matrix | クレデンシャル × ホスト スプレーマトリックス |
| Priority | スコアリング上位ホスト（🥇🥈🥉 メダル表示） |
| Focus | 各ターゲットの詳細列挙結果（drill モードのみ） |
| Commands | 実行コマンド全履歴（出力・コピーボタン付き） |
| Checklist | レポート用マークダウンチェックリスト自動生成 |
| HTTP Links | HTTP/HTTPS サービスへのワンクリックリンク |
| /etc/hosts | /etc/hosts 追記用エントリ自動生成（コピーボタン付き） |

**focus レポート（単一ホスト）**

| タブ | 内容 |
|-----|------|
| ⚠ Critical | SMB 共有 / Vuln 発見 / ユーザー一覧 / 無認証アクセス |
| TCP/UDP Ports | 開放ポート一覧（高価値ポートはハイライト） |
| Vuln Scan | nmap --script vuln の解析結果 |
| UDP Raw | UDP スキャン生出力 |
| SMB Details | enum4linux-ng 解析（ユーザー・共有・パスワードポリシー） |
| HTTP | feroxbuster / whatweb / curl ヘッダー解析 |
| Command Log | 全コマンド履歴（コピーボタン付き） |

### マークダウンエクスポート

各テーブルの隣にある **Copy Markdown** ボタンでマークダウン形式の表をワンクリックコピーできます。レポート（VSCode / VSCodium）への貼り付けが簡単になります。

---

## 🏗️ コードの構成

```
proxenum/
├── proxenum.py          # エントリポイント・CLI 引数定義
└── core/
    ├── models.py        # データモデル（EnumSession, Host, CredentialResult, CommandRecord）
    ├── smb.py           # SMB 列挙（nxc smb）
    ├── nmap.py          # ポートスキャン（rustscan + nmap -p- + nmap -sCV）
    ├── focus.py         # 単一ホスト深堀り列挙（サービス別ディスパッチ）
    ├── enum_extra.py    # 追加列挙（SMB 匿名・LDAP・AS-REP・Kerberoast）
    ├── spray.py         # パスワードスプレー（nxc smb/winrm）
    ├── stax.py          # 静的解析（NTLM クラック・Mimikatz 解析・PEAS 解析）
    ├── report.py        # HTML レポート生成（ReportGenerator + FocusReport）
    ├── parsers.py       # 出力解析（enum4linux / nmap vuln / whatweb / nxc shares）
    ├── scoring.py       # ホストスコアリング（drill モード用）
    ├── scanlog.py       # proxscan.N.json の読み書き
    ├── heartbeat.py     # 進行状況表示（HeartBeat）
    ├── runner.py        # コマンド実行ラッパー（CommandRecord 記録）
    ├── quotes.py        # 起動時名言
    └── template.html   # HTML レポートテンプレート
```

### データフロー

```
EnumSession（セッション状態）
    │
    ├── hosts: {ip → Host}
    │       ├── open_ports: {port → service}
    │       ├── udp_ports: {port → service}
    │       ├── hostname / fqdn / domain / os_info
    │       └── smb_signing / smbv1
    │
    ├── credentials: [CredentialResult]
    │       └── username / password / ip / protocol / success / is_admin
    │
    └── command_history: [CommandRecord]
            └── command / output / return_code / duration / label / timestamp
```

---

## 💡 活用パターン

### 1. 内部ネットワーク侵入後（SOCKS プロキシ経由）

```bash
# ステップ1：chisel でプロキシ確立後、全ホスト一括スキャン
python3 proxenum.py scan -i ip.txt --proxy

# ステップ2：クレデンシャルとユーザーリストが揃ったらスプレー
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt --proxy
```

### 2. ligolo-ng トンネル確立後

```bash
# ステップ1：全体スキャン + 上位 3 ホストを深堀り
python3 proxenum.py drill -i ip.txt --ligolo --top 3

# ステップ2：特定ホストを詳細調査
python3 proxenum.py focus -i 10.10.10.50 --ligolo --web-exts php,html
```

### 3. 侵害後の解析

```bash
# Mimikatz ダンプ解析 → ユーザー・ハッシュ抽出
python3 proxenum.py stax --mimi-check mimikatz_output.txt

# 抽出したハッシュをクラック
python3 proxenum.py stax --crack-ntlm mimi_ntlm.hash

# WinPEAS で権限昇格手掛かりを検索
python3 proxenum.py stax --winpeas-check winpeas.txt

# ユーザーリストを統合
python3 proxenum.py stax --merge-file users_smb.txt users_ldap.txt -o all_users.txt
```

### 4. ログを使って再スキャンを省略

```bash
# 初回スキャン（ポート情報を proxscan.1.json に保存）
python3 proxenum.py scan -i ip.txt

# 2回目（ポートスキャンをスキップ、クレデンシャルが揃ったのでスプレーのみ）
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt
# → 自動的に proxscan.1.json を読み込みポートスキャンをスキップ
```
