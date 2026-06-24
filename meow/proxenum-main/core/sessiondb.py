"""Unified persistent session store — proxenum.json in cwd.

All modes (scan / focus / drill) read and write to the same file so information
accumulates across runs without duplication. Command history (scan results) is
persisted per-host so focus can resume without re-running completed phases.
"""
import json
from datetime import datetime
from pathlib import Path
from .models import EnumSession, CredentialResult, CommandRecord

_DB_FILE = "proxenum.json"
_OUTPUT_CAP = 65536  # 64 KB per command output stored in DB


def _ip_key(ip: str) -> str:
    """Stable machine identity across OffSec lab IP shifts.

    On reboot OffSec re-assigns the 3rd octet (the per-session subnet) while the
    last octet — the machine's identity — stays constant:
        192.168.141.156  →  192.168.241.156   (3rd: 141→241, 4th: 156 fixed)
    So we key on octets 1, 2 and 4, ignoring the volatile 3rd octet.
    """
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[3]}" if len(parts) == 4 else ip


# Backwards-compatible alias (older name)
_last3 = _ip_key


def db_path(directory: Path | None = None) -> Path:
    return (directory or Path(".")) / _DB_FILE


def save(session: EnumSession, version: str = "1.6.3",
         directory: Path | None = None, target_ip: str | None = None,
         full_history: bool = False):
    """Merge session into proxenum.json (upsert — never loses existing data).

    full_history=True additionally persists the *entire* session command history
    in a top-level ``command_history`` list (deduplicated by label). This is used
    by adenum, whose commands span many hosts and are not tied to a single
    target IP, so subsequent runs can skip already-completed steps (port scans,
    sprays, roasting…) instead of re-running them.
    """
    path = db_path(directory)
    existing = _load_raw(path)

    # --- domain ---
    if session.domain not in ("Unknown", ""):
        existing["domain"] = session.domain

    # --- hosts ---
    hosts_db: dict = existing.setdefault("hosts", {})
    for ip, h in session.hosts.items():
        hd = hosts_db.setdefault(ip, {})
        _merge_str(hd, "hostname", h.hostname)
        _merge_str(hd, "fqdn", h.fqdn)
        _merge_str(hd, "domain", h.domain)
        _merge_str(hd, "os_info", h.os_info)
        hd["smb_signing"] = h.smb_signing
        hd["smbv1"] = h.smbv1
        # Ports — always add newly discovered ports
        op: dict = hd.setdefault("open_ports", {})
        for p, svc in h.open_ports.items():
            op[str(p)] = svc
        udp: dict = hd.setdefault("udp_ports", {})
        for p, svc in h.udp_ports.items():
            udp[str(p)] = svc

    # --- command history — save per target IP ---
    # Only write history for the target IP (focus/drill) to avoid bloating
    if target_ip and target_ip in hosts_db:
        history_key = "command_history"
        stored: list[dict] = hosts_db[target_ip].setdefault(history_key, [])
        stored_cmds = {r["command"] for r in stored}
        for rec in session.command_history:
            if rec.command in stored_cmds:
                continue  # skip duplicates
            stored.append({
                "label": rec.label,
                "command": rec.command,
                "output": rec.output[:_OUTPUT_CAP],  # cap size
                "rc": rec.return_code,
                "duration": round(rec.duration, 2),
                "ts": rec.timestamp.isoformat(),
            })
            stored_cmds.add(rec.command)

    # --- full command history (adenum) — top-level, dedup by label ---
    # Labels are stable logical-step identifiers (e.g. "Nmap detail 10.0.0.5",
    # "SMB spray") so we key on them; this keeps spray records (whose command
    # embeds a per-run temp file path) from accumulating on every run.
    if full_history:
        global_hist: list = existing.setdefault("command_history", [])
        seen_labels = {r.get("label") for r in global_hist if r.get("label")}
        seen_cmds = {r.get("command") for r in global_hist}
        for rec in session.command_history:
            key = rec.label or rec.command
            if rec.label and rec.label in seen_labels:
                continue
            if not rec.label and rec.command in seen_cmds:
                continue
            global_hist.append({
                "label": rec.label,
                "command": rec.command,
                "output": rec.output[:_OUTPUT_CAP],
                "rc": rec.return_code,
                "duration": round(rec.duration, 2),
                "ts": rec.timestamp.isoformat(),
            })
            if rec.label:
                seen_labels.add(rec.label)
            seen_cmds.add(rec.command)

    # --- credentials (dedup by username+ip+protocol+local_auth) ---
    creds_db: list = existing.setdefault("credentials", [])
    existing_keys = {
        (c["username"], c["ip"], c["protocol"], c.get("local_auth", False))
        for c in creds_db
    }
    for c in session.credentials:
        if not c.success:
            continue
        key = (c.username, c.ip, c.protocol, c.local_auth)
        if key not in existing_keys:
            creds_db.append({
                "username": c.username,
                "password": c.password,
                "ip": c.ip,
                "protocol": c.protocol,
                "is_admin": c.is_admin,
                "is_ntlm": c.is_ntlm,
                "local_auth": c.local_auth,
            })
            existing_keys.add(key)

    existing["updated"] = datetime.now().isoformat()
    existing.setdefault("created", existing["updated"])
    existing["version"] = version

    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")


def load(session: EnumSession, directory: Path | None = None,
         target_ip: str | None = None, full_history: bool = False) -> bool:
    """Load proxenum.json into session (merge). Returns True if ports were loaded.

    If target_ip is given, also restores command_history for that host so
    subsequent focus runs can skip already-completed phases.

    full_history=True restores the top-level ``command_history`` (written by
    adenum) so multi-host AD runs resume without re-scanning/re-spraying.
    """
    path = db_path(directory)
    if not path.exists():
        return False
    data = _load_raw(path)

    if data.get("domain", "Unknown") not in ("Unknown", "") and session.domain == "Unknown":
        session.domain = data["domain"]

    saved_hosts: dict = data.get("hosts", {})
    exact_loaded: set[str] = set()

    def _load_host_data(ip: str, hd: dict, restore_history: bool = False):
        host = session.get_or_create_host(ip)
        _apply_str(host, "hostname", hd.get("hostname"))
        _apply_str(host, "fqdn", hd.get("fqdn"))
        if hd.get("domain"):
            host.domain = hd["domain"]
        if hd.get("os_info") and hd["os_info"] != "Unknown":
            host.os_info = hd["os_info"]
        host.smb_signing = hd.get("smb_signing", host.smb_signing)
        host.smbv1 = hd.get("smbv1", host.smbv1)
        for p_str, svc in hd.get("open_ports", {}).items():
            host.open_ports.setdefault(int(p_str), svc)
        for p_str, svc in hd.get("udp_ports", {}).items():
            host.udp_ports.setdefault(int(p_str), svc)
        if restore_history and hd.get("command_history"):
            existing_cmds = {r.command for r in session.command_history}
            for rec_d in hd["command_history"]:
                if rec_d.get("command") in existing_cmds:
                    continue
                try:
                    ts = datetime.fromisoformat(rec_d.get("ts", datetime.now().isoformat()))
                except ValueError:
                    ts = datetime.now()
                session.command_history.append(CommandRecord(
                    command=rec_d["command"],
                    output=rec_d.get("output", ""),
                    return_code=rec_d.get("rc", 0),
                    duration=rec_d.get("duration", 0.0),
                    label=rec_d.get("label", ""),
                    timestamp=ts,
                ))

    # full_history restores per-host history for *every* loaded host so adenum
    # (multi-host) inherits prior drill/focus scans — e.g. a drill "Nmap detail"
    # is reused instead of re-running -sCV.
    for ip, hd in saved_hosts.items():
        _load_host_data(ip, hd, restore_history=(full_history or ip == target_ip))
        exact_loaded.add(ip)

    # OffSec lab IP shift fallback: match on octets 1.2.x.4 (3rd octet changes
    # on reboot, last octet is the machine identity).
    if session.input_ips:
        saved_by_key = {_ip_key(sip): sip for sip in saved_hosts}
        for target in session.input_ips:
            if target in exact_loaded:
                continue
            match = saved_by_key.get(_ip_key(target))
            if match:
                _load_host_data(target, saved_hosts[match],
                                restore_history=(full_history or target == target_ip))

    # Restore top-level command history (adenum resume)
    if full_history:
        existing_labels = {r.label for r in session.command_history if r.label}
        existing_cmds = {r.command for r in session.command_history}
        for rec_d in data.get("command_history", []):
            lbl = rec_d.get("label", "")
            cmd = rec_d.get("command", "")
            if lbl and lbl in existing_labels:
                continue
            if not lbl and cmd in existing_cmds:
                continue
            try:
                ts = datetime.fromisoformat(rec_d.get("ts", datetime.now().isoformat()))
            except ValueError:
                ts = datetime.now()
            session.command_history.append(CommandRecord(
                command=cmd,
                output=rec_d.get("output", ""),
                return_code=rec_d.get("rc", 0),
                duration=rec_d.get("duration", 0.0),
                label=lbl,
                timestamp=ts,
            ))
            if lbl:
                existing_labels.add(lbl)
            existing_cmds.add(cmd)

    for cd in data.get("credentials", []):
        session.credentials.append(CredentialResult(
            username=cd["username"],
            password=cd.get("password", ""),
            ip=cd["ip"],
            protocol=cd["protocol"],
            success=True,
            is_admin=cd.get("is_admin", False),
            is_ntlm=cd.get("is_ntlm", False),
            local_auth=cd.get("local_auth", False),
        ))

    return any(h.open_ports for h in session.hosts.values())


def info(directory: Path | None = None) -> dict | None:
    """Return summary dict or None if no db file."""
    path = db_path(directory)
    if not path.exists():
        return None
    try:
        data = _load_raw(path)
        host_info = {}
        for ip, hd in data.get("hosts", {}).items():
            host_info[ip] = {
                "ports": len(hd.get("open_ports", {})),
                "commands": len(hd.get("command_history", [])),
            }
        return {
            "path": path,
            "created": data.get("created", "?"),
            "updated": data.get("updated", "?"),
            "domain": data.get("domain", "Unknown"),
            "host_count": len(data.get("hosts", {})),
            "host_info": host_info,
            "global_commands": len(data.get("command_history", [])),
            "cred_count": len(data.get("credentials", [])),
            "version": data.get("version", "?"),
        }
    except Exception:
        return None


def has_scan_results(directory: Path | None, ip: str) -> bool:
    """Return True if there are saved command_history records for this IP."""
    data = _load_raw(db_path(directory))
    hd = data.get("hosts", {}).get(ip, {})
    return bool(hd.get("command_history"))


# ── internal helpers ───────────────────────────────────────────────────────

def _load_raw(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _merge_str(d: dict, key: str, value: str):
    if value not in (None, "Unknown", "") and d.get(key, "Unknown") in ("Unknown", "", None):
        d[key] = value


def _apply_str(obj, attr: str, value):
    if value and value != "Unknown" and getattr(obj, attr, "Unknown") in ("Unknown", ""):
        setattr(obj, attr, value)
