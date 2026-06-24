# proxenum — 裏側で何が動いているか

> v1.5.5 | Recon Suite
> 試験前チューニング用リファレンス

---

## 目次

- [scan](#scan)
- [focus](#focus)
- [drill](#drill)
- [データファイル（proxenum.json）](#データファイル)
- [オプション早見表](#オプション早見表)

---

## scan

**使い方**
```
proxenum scan -i targets.txt [-u users.txt] [-p pass.txt] [-n hashes.txt]
```

### Phase 1 — SMB Enumeration（常に実行）

```bash
nxc smb <targets>
```

全ターゲット一括。結果から以下を抽出する：
- Hostname / FQDN / Domain
- SMB Signing（`False` → リレー候補 ⚡ に表示）
- SMBv1 の有無 / OS情報

---

### Phase 2 — Port Scan

4つのモードがある。どれか1つが走る。

#### ① 通常モード（デフォルト）

```bash
# Step 1: rustscan（高速非同期）と nmap -p- を並列実行
rustscan -a <ip> --ulimit 5000 -b 1000
sudo nmap -p- --min-rate 1000 -T4 -Pn --open -oG - <ip>

# Step 2: 両方の結果をマージし、確定ポートに1回だけ詳細スキャン
sudo nmap -sCV -Pn -p<ports> -oA <host>/nmap/detail <ip>

# Step 3: XMLをHTMLに変換
xsltproc -o <host>/detail.html /usr/share/nmap/nmap.xsl detail.xml
```

> rustscan と nmap -p- は **並列実行**。両方終わってから nmap -sCV を1回だけ。

#### ② Fast mode（`--top-ports N`）

```bash
sudo nmap -sCV -Pn --top-ports <N> --max-retries 1 --host-timeout 120s -oA detail <ip>
```

#### ③ Proxy mode（`--proxy`）

```bash
# proxychains 経由。SYN不可なので -sT（TCP connect）。top-30のみ。
nmap -sT -Pn -T4 --top-ports 30 --max-retries 1 --host-timeout 90s -oG - <ip>
```

#### ④ Ligolo mode（`--ligolo`）

```bash
rustscan -a <ip> --ulimit 2000 -b 500
sudo nmap -p- --min-rate 500 -T3 -Pn -oA full <ip>
sudo nmap -sCV -Pn -p<ports> --max-retries 2 --host-timeout 300s -oA detail <ip>
```

---

### Phase 3 — Extra Enumeration（`--proxy` 以外で実行）

#### Anonymous phase

| ポート | コマンド |
|--------|---------|
| 445 | `nxc smb <ip> -u "" -p "" --shares` |
| 445 | `nxc smb <ip> -u "guest" -p "" --shares` |
| 445 | `enum4linux-ng -A <ip>` |
| 389/636 | `nxc ldap <ip> -u "" -p "" --users` |
| 389/636 | `ldapsearch -H ldap://<ip> -x -b DC=... (objectClass=user)` |
| 88（Kerberos）+ -u 指定あり | `impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <ip> -format hashcat` |

#### Authenticated phase（spray 成功後に自動実行）

| ポート | コマンド |
|--------|---------|
| 445 | `nxc smb <ip> -u <user> -p <pass> --shares / --users / --groups` |
| 389/636 | `nxc ldap <ip> -u <user> -p <pass> --users / --groups / --password-not-required / --admin-count` |
| 88（DC）| `impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request` ← **Kerberoast** |

---

### Phase 4 — Password Spray（`-u` + `-p` or `-n` 指定時）

v1.5.5 以降、`--local-auth` オプションは廃止。**常時ドメイン認証とローカル認証の両方**を試みる。

```bash
# 各プロトコル × ドメイン認証 + ローカル認証 = 6コマンドずつ
nxc smb   <targets> -u <users> -p <passwords>
nxc smb   <targets> -u <users> -p <passwords> --local-auth
nxc winrm <targets> -u <users> -p <passwords>
nxc winrm <targets> -u <users> -p <passwords> --local-auth
nxc rdp   <targets> -u <users> -p <passwords>
nxc rdp   <targets> -u <users> -p <passwords> --local-auth

# NTLMハッシュも同様
nxc smb   <targets> -u <users> -H <hashes>
nxc smb   <targets> -u <users> -H <hashes> --local-auth
# ... (winrm, rdp も同様)
```

レポートには **DOMAIN** / **LOCAL** バッジで認証方式を表示。

---

## focus

**使い方**
```
proxenum focus -i <IP> [--web-exts php,html] [--fw N] [--fl N] [--fs N] [--recurse]
```

レポートは **フェーズごとに段階的に** 書き出される（Phase 1→2→3）。

---

### Phase 1 — SMB Pre-check + TCP Scan

```bash
# SMB情報収集（Hostname/Domain取得）
nxc smb <ip>

# TCP スキャン（drill 経由なら既存ポートを再利用して nmap -sCV のみ）
rustscan -a <ip> --ulimit 5000 -b 1000   # 並列
sudo nmap -p- --min-rate 1000 -T4 -Pn --open -oG - <ip>  # 並列
sudo nmap -sCV -Pn -p<ports> -oA focus_<ip>/nmap/detail <ip>
```

---

### Phase 2 — Vuln Scan + UDP + SNMP

```bash
# Vuln スクリプト
sudo nmap --script vuln -Pn -p<ports> -oA focus_<ip>/nmap/vuln <ip>

# UDP top-20
sudo nmap -sU --top-ports 20 -Pn -oA focus_<ip>/nmap/udp <ip>

# SNMP（UDP/161 が開いていた場合）
snmp-check <ip> -c public               # → focus_<ip>/snmp-check.txt に保存
# 失敗した場合のフォールバック:
onesixtyone <ip> public

# SNMP出力からバージョン情報を抽出してsearchsploit
searchsploit "<product> <version>"      # SNMP由来のクエリ、最大5個
```

---

### Phase 3 — Per-port Service Enumeration

#### SMB（139 or 445）

```bash
nxc smb <ip> -u "" -p "" --shares
nxc smb <ip> -u "" -p "" --users
nxc smb <ip> -u "guest" -p "" --shares
nxc smb <ip> -u "guest" -p "" --users
smbclient -L //<ip>/ -N
enum4linux-ng -A <ip>
```

#### HTTP / HTTPS（80, 443, 8080, 8443）

```bash
# Tech detection
whatweb http://<ip> -a 3

# Header grab
curl -sI --connect-timeout 5 --max-time 10 http://<ip>

# Directory brute-force
feroxbuster -u http://<ip> -w raft-medium-directories-lowercase.txt \
  --silent --no-state -t 50 [-n] [-x <exts>] [--filter-words N] [--filter-lines N] [--filter-size N]
# -n はデフォルト（再帰なし）。 --recurse を渡すと -n が外れる。

# ↳ feroxbuster の結果から追加アクション（自動）:
#   /.git が見えた場合:
git-dumper http://<ip>/.git/ focus_<ip>/git_dump/   # 🔴 Critical

#   LFI疑いのパラメータ（page=, file=, path= 等）を検出した場合:
#   → CommandRecord として履歴に記録、レポートにオレンジ警告として表示

# WebDAV チェック
davtest -url http://<ip>

# WebDAV OPTIONS + PROPFIND プローブ
curl -sk -X OPTIONS --connect-timeout 5 -D - -o /dev/null http://<ip>
# Allow: ヘッダーに DAV メソッドが含まれる場合:
curl -sk -X PROPFIND --connect-timeout 5 -D - -o /dev/null http://<ip>
# 207 → 認証なしでDAV操作可、401 → 認証必要

# VHost discovery（Domain が判明しているとき）
ffuf -u http://<ip> -H "Host: FUZZ.<domain>" -w subdomains-top1million-5000.txt -t 50 -v -ac

# バージョン情報から自動 searchsploit（whatweb/nmap 出力をパース）
searchsploit "<product> <version>"   # 最大6クエリ・DoS/XSS除外・RCEは🔴マーク
```

#### LDAP（389, 636）

```bash
nxc ldap <ip> -u "" -p "" --users
nxc ldap <ip> -u "guest" -p "" --users
ldapsearch -H ldap://<ip> -x -b "DC=..." sAMAccountName description memberOf
```

#### FTP（21）

```bash
nxc ftp <ip> -u anonymous -p anonymous
```

#### SSH（22）

```bash
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes <ip> exit
```

#### RDP（3389）← v1.5.5 追加

```bash
nxc rdp <ip>
```

#### MSSQL（1433）

```bash
nxc mssql <ip>
nxc mssql <ip> -u sa -p ""
nxc mssql <ip> -u sa -p sa
```

#### MySQL（3306）

```bash
nxc mysql <ip> -u root -p ""
nxc mysql <ip> -u "" -p ""
```

#### PostgreSQL（5432）

```bash
nxc postgres <ip> -u postgres -p ""
```

#### Redis（6379）

```bash
redis-cli -h <ip> ping
redis-cli -h <ip> info
```

#### SMTP（25）

```bash
nxc smtp <ip>
```

---

## drill

**使い方**
```
proxenum drill -i targets.txt [--top 3] [--ligolo] [--top-ports N] ...
```

### フロー

```
1. proxenum.json 読み込み（過去の scan 結果を引き継ぎ）
2. SMB Enum（全ターゲット）
3. Port Scan（全ターゲット） ← db にポートがあればスキップ
4. 初期スコアリング → top N を選出
5. focus × N（各ホストを個別に深掘り）
6. focus 結果を proxenum.json に書き込み
7. 最終スコアリング（post-focus）→ 攻撃優先度ランキング表示
8. ドリルレポート生成
```

### 最終ランキング（drill 専用）

focus 完了後、以下のボーナスを含む **最終スコア** でランキングし直す：

| 発見内容 | ボーナス |
|---------|---------|
| 👑 Admin creds 取得 | +30 |
| 🔑 有効な認証情報 | +15 |
| 🔴 WebDAV PUT で実行可能ファイルアップロード | +20 |
| 🔴 .git ディレクトリ露出・ダンプ成功 | +18 |
| ⚠ LFI パラメータ検出 | +10 |
| 📡 SNMP public コミュニティ読み取り可能 | +8 |
| ⚡ SMB リレー候補 | +6 |
| 💥 Vuln scan で VULNERABLE 検出 | +12 |

---

## データファイル

### proxenum.json（v1.5.5〜）

カレントディレクトリに作成される**共通セッションデータベース**。全モードで読み書きされる。

```json
{
  "version": "1.5.5",
  "created": "2025-...",
  "updated": "2025-...",
  "domain": "corp.local",
  "hosts": {
    "10.0.0.1": {
      "hostname": "DC01",
      "fqdn": "dc01.corp.local",
      "open_ports": {"445": "microsoft-ds", "80": "http"},
      "udp_ports": {"161": "snmp"},
      "smb_signing": true
    }
  },
  "credentials": [
    {"username": "admin", "password": "pass123", "ip": "10.0.0.1",
     "protocol": "SMB", "is_admin": true, "local_auth": false}
  ]
}
```

**ワークフロー例:**
```
proxenum scan -i targets.txt           # hosts + ports → proxenum.json
proxenum focus -i 10.0.0.1            # ポートを db から読み込み、詳細結果を書き込み
proxenum scan -i targets.txt -u users.txt -p pass.txt  # creds も追記
```

`--skip-log` でこのファイルを無視してフレッシュスキャン。

---

## オプション早見表

| オプション | 対象 | 効果 |
|-----------|------|------|
| `--top-ports N` | scan/focus/drill | rustscan・nmap -p- をスキップして top N だけ |
| `--proxy` | scan | proxychains 経由の -sT スキャン、top-30のみ |
| `--ligolo` | scan/focus/drill | TUNインターフェース向け保守的パラメータ |
| `--no-brute` | scan | nxc --no-brute（1:1ペアリング） |
| `--no-portscan` | scan | Nmap スキャン全スキップ |
| `--web-exts php,asp` | focus/drill | feroxbuster に `-x php,asp` を追加 |
| `--fw N` | focus/drill | feroxbuster `--filter-words N` |
| `--fl N` | focus/drill | feroxbuster `--filter-lines N` |
| `--fs N` | focus/drill | feroxbuster `--filter-size N` |
| `--recurse` | focus/drill | feroxbuster の `-n`（no-recursion）を外す |
| `--skip-log` | scan/focus/drill | proxenum.json を無視・読み書きしない |
| `--no-report` | scan/focus/drill | HTMLレポート生成をスキップ |

> `--local-auth` は v1.5.5 で廃止。常時ドメイン+ローカル両方を試みる。

---

## ファイル出力まとめ

| 何 | どこ |
|----|------|
| セッション DB | `./proxenum.json`（全モード共通） |
| Nmap XML/HTML | `<hostname>/nmap/detail.*` |
| SNMP チェック結果 | `focus_<ip>/snmp-check.txt` |
| git dump | `focus_<ip>/git_dump/` |
| Focus レポート | `focus.html`（フェーズごとに上書き） |
| Scan/Drill レポート | `scan_<N>.html` / `drill_<N>.html` |
