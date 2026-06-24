"""Persistent scan state — save/load to skip re-scanning on subsequent runs."""
import json
import re
from datetime import datetime
from pathlib import Path
from .models import EnumSession

_LOG_GLOB = "proxscan.*.json"
_LOG_RE = re.compile(r"proxscan\.(\d+)\.json$")


def _log_paths(directory: Path) -> list[Path]:
    files = [p for p in directory.glob("proxscan.*.json") if _LOG_RE.search(p.name)]
    return sorted(files, key=lambda p: int(_LOG_RE.search(p.name).group(1)))


def latest_log(directory: Path | None = None) -> Path | None:
    paths = _log_paths(directory or Path("."))
    return paths[-1] if paths else None


def next_log_path(directory: Path | None = None) -> Path:
    directory = directory or Path(".")
    paths = _log_paths(directory)
    n = int(_LOG_RE.search(paths[-1].name).group(1)) + 1 if paths else 1
    return directory / f"proxscan.{n}.json"


def save(session: EnumSession, path: Path, version: str = "1.4.0"):
    data = {
        "created": datetime.now().isoformat(),
        "version": version,
        "domain": session.domain,
        "hosts": {
            ip: {
                "hostname": h.hostname,
                "fqdn": h.fqdn,
                "domain": h.domain,
                "os_info": h.os_info,
                "smb_signing": h.smb_signing,
                "smbv1": h.smbv1,
                "open_ports": {str(p): s for p, s in h.open_ports.items()},
                "udp_ports": {str(p): s for p, s in h.udp_ports.items()},
            }
            for ip, h in session.hosts.items()
        },
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load(path: Path, session: EnumSession) -> str:
    """Load scan log into session. Returns ISO timestamp string of when log was created."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("domain", "Unknown") not in ("Unknown", "") and session.domain == "Unknown":
        session.domain = data["domain"]
    for ip, hd in data.get("hosts", {}).items():
        host = session.get_or_create_host(ip)
        if host.hostname == "Unknown" and hd.get("hostname") not in (None, "Unknown", ""):
            host.hostname = hd["hostname"]
        if host.fqdn == "Unknown" and hd.get("fqdn") not in (None, "Unknown", ""):
            host.fqdn = hd["fqdn"]
        if hd.get("domain"):
            host.domain = hd["domain"]
        if hd.get("os_info"):
            host.os_info = hd["os_info"]
        host.smb_signing = hd.get("smb_signing", host.smb_signing)
        host.smbv1 = hd.get("smbv1", host.smbv1)
        for p_str, svc in hd.get("open_ports", {}).items():
            host.open_ports.setdefault(int(p_str), svc)
        for p_str, svc in hd.get("udp_ports", {}).items():
            host.udp_ports.setdefault(int(p_str), svc)
    return data.get("created", "unknown")


def list_logs(directory: Path | None = None) -> list[dict]:
    """Return info dicts for all log files in directory."""
    result = []
    for p in _log_paths(directory or Path(".")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            result.append({
                "path": p,
                "created": data.get("created", "?"),
                "domain": data.get("domain", "?"),
                "host_count": len(data.get("hosts", {})),
                "version": data.get("version", "?"),
            })
        except Exception:
            result.append({"path": p, "created": "?", "domain": "?", "host_count": 0, "version": "?"})
    return result
