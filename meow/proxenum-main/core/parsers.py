import re
from dataclasses import dataclass, field


@dataclass
class Enum4LinuxResult:
    users: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    shares: list[tuple[str, str]] = field(default_factory=list)
    password_policy: dict[str, str] = field(default_factory=dict)
    os_info: str = ""


def parse_enum4linux(output: str) -> Enum4LinuxResult:
    r = Enum4LinuxResult()

    # Users: "username:XXX, rid:YYY" or "user:[XXX] rid:[YYY]"
    for m in re.finditer(r"username:([^,\s]+)", output, re.I):
        u = m.group(1).strip()
        if u and u not in r.users:
            r.users.append(u)
    for m in re.finditer(r"user:\[([^\]]+)\]", output, re.I):
        u = m.group(1).strip()
        if u and u not in r.users:
            r.users.append(u)

    # Groups
    for m in re.finditer(r"group:\[([^\]]+)\]", output, re.I):
        g = m.group(1).strip()
        if g and g not in r.groups:
            r.groups.append(g)
    for m in re.finditer(r"Groupname:\s*(\S+)", output, re.I):
        g = m.group(1).strip()
        if g and g not in r.groups:
            r.groups.append(g)

    # Shares — two formats:
    #   "Share: NAME, Type: DISK$, Remark: ..."
    for m in re.finditer(r"Share:\s*(\S+),\s*Type:\s*\S+,\s*Remark:\s*(.*)", output, re.I):
        name, remark = m.group(1), m.group(2).strip()
        if not any(s[0] == name for s in r.shares):
            r.shares.append((name, remark))
    #   Table: "Sharename    Type    Comment"
    in_table = False
    for line in output.splitlines():
        if re.search(r"Sharename\s+Type\s+Comment", line, re.I):
            in_table = True
            continue
        if in_table:
            m = re.match(r"\s{2,}(\S+)\s+(?:Disk|IPC|Printer)\s*(.*)", line, re.I)
            if m:
                n2, rm = m.group(1), m.group(2).strip()
                if not any(s[0] == n2 for s in r.shares):
                    r.shares.append((n2, rm))
            elif line.strip() == "" or re.match(r"\s*-{4,}", line):
                in_table = False

    # Password policy
    for pat, key in [
        (r"Minimum password length[:\s]+(\S+)", "Min length"),
        (r"Password history length[:\s]+(\S+)", "History"),
        (r"Account Lockout Threshold[:\s]+(\S+)", "Lockout threshold"),
        (r"Minimum password age[:\s]+(.+)", "Min age"),
    ]:
        m = re.search(pat, output, re.I)
        if m:
            r.password_policy[key] = m.group(1).strip()

    # OS
    m = re.search(r"OS:\s*(.+)", output, re.I)
    if m:
        r.os_info = m.group(1).strip()

    return r


@dataclass
class VulnFinding:
    port: int
    script: str
    detail: str


def parse_nmap_vuln(output: str) -> list[VulnFinding]:
    findings: list[VulnFinding] = []
    cur_port = 0
    cur_script = ""
    buf: list[str] = []

    _VULN_KEYWORDS = {"vuln", "cve-", "exploit", "shellshock", "heartbleed", "ms17-010",
                      "eternalblue", "smb-vuln", "ssl-poodle", "ssl-ccs"}

    def _flush():
        if cur_script and buf:
            text = " ".join(buf).strip()
            if any(kw in cur_script.lower() or kw in text.lower() for kw in _VULN_KEYWORDS):
                findings.append(VulnFinding(cur_port, cur_script, text))

    for line in output.splitlines():
        pm = re.match(r"(\d+)/tcp\s+open", line)
        if pm:
            _flush()
            cur_port = int(pm.group(1))
            cur_script, buf = "", []
            continue
        sm = re.match(r"\|[_\s]*([a-z][a-z0-9_-]+):\s*(.*)", line)
        if sm and cur_port:
            if sm.group(1) != cur_script:
                _flush()
            cur_script = sm.group(1)
            if sm.group(2).strip():
                buf = [sm.group(2).strip()]
            else:
                buf = []
            continue
        if cur_script and line.startswith("|"):
            buf.append(line.lstrip("| ").strip())

    _flush()
    return findings


def parse_feroxbuster(output: str) -> list[tuple[int, str]]:
    """Return [(status_code, url)] for interesting finds."""
    results = []
    for line in output.splitlines():
        m = re.search(r"\b(\d{3})\b.*?(https?://\S+)", line)
        if m:
            status = int(m.group(1))
            url = m.group(2).rstrip("/,")
            if status not in (404,) and url not in [r[1] for r in results]:
                results.append((status, url))
    return results


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_whatweb(output: str) -> list[tuple[str, str]]:
    """Strip ANSI, return [(tech_name, detail)] from whatweb output."""
    clean = _ANSI_RE.sub("", output)
    _SKIP = {"http", "https", "redirect-to", "ip", "title", "country", "email",
              "requestconfig", "target", "summary"}
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in clean.splitlines():
        if not line.strip() or line.upper().startswith("ERROR"):
            continue
        for m in re.finditer(r"([\w][\w\-\.]{1,40})\[([^\]]{0,200})\]", line):
            name = m.group(1).strip()
            detail = m.group(2).strip()
            if name.lower() in _SKIP or name.isdigit():
                continue
            key = name.lower()
            if key not in seen:
                seen.add(key)
                results.append((name, detail))
    return results


def parse_curl_headers(output: str) -> list[tuple[str, str]]:
    """Parse curl -sI output into [(header_name, value)] list."""
    clean = _ANSI_RE.sub("", output)
    headers: list[tuple[str, str]] = []
    for line in clean.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("HTTP/"):
            headers.append(("Status", line))
            continue
        m = re.match(r"^([^:]+):\s*(.*)", line)
        if m:
            headers.append((m.group(1).strip(), m.group(2).strip()))
    return headers


def parse_nxc_shares(output: str) -> list[tuple[str, str, str]]:
    """Parse nxc smb --shares output into [(share_name, permissions, remark)].

    nxc table format after '[*] Enumerated shares':
      SMB  IP  PORT  HOST  SHARENAME   READ,WRITE   Remark
    """
    results: list[tuple[str, str, str]] = []
    _SKIP_NAMES = {"share", "sharename", "name", "-----", "----"}
    in_table = False

    for line in output.splitlines():
        # Gate: start parsing only after '[*] Enumerated shares'
        if re.search(r"\[\*\]\s+Enumerated shares", line, re.I):
            in_table = True
            continue
        if not in_table:
            continue
        # Skip divider / header rows
        if re.search(r"Share\s+Permissions|-----\s+", line, re.I):
            continue
        # nxc line: "SMB  IP  PORT  HOSTNAME  SHARENAME  PERMS  REMARK"
        m = re.match(
            r"SMB\s+\S+\s+\d+\s+\S+\s+"        # "SMB ip port host "
            r"([\w\$\-\.]+)"                       # share name
            r"\s*(READ(?:,WRITE)?|WRITE|NO ACCESS|)\s*(.*)",  # perms + remark
            line, re.I,
        )
        if m:
            name = m.group(1).strip()
            perms = m.group(2).strip().upper()
            remark = m.group(3).strip()
            if name.lower() in _SKIP_NAMES:
                continue
            if not any(r[0] == name for r in results):
                results.append((name, perms or "—", remark))
    return results
