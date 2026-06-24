from .models import Host, EnumSession

_PORT_SCORES: dict[int, tuple[int, str]] = {
    21:    (8,  "FTP"),
    22:    (4,  "SSH"),
    23:    (12, "Telnet"),
    25:    (5,  "SMTP"),
    53:    (4,  "DNS"),
    80:    (8,  "HTTP"),
    88:    (8,  "Kerberos"),
    110:   (3,  "POP3"),
    143:   (3,  "IMAP"),
    389:   (7,  "LDAP"),
    443:   (8,  "HTTPS"),
    445:   (12, "SMB"),
    636:   (7,  "LDAPS"),
    1433:  (18, "MSSQL"),
    1521:  (14, "Oracle"),
    3306:  (12, "MySQL"),
    3389:  (10, "RDP"),
    5432:  (12, "PostgreSQL"),
    5985:  (14, "WinRM"),
    5986:  (14, "WinRM-S"),
    6379:  (14, "Redis"),
    8080:  (7,  "HTTP-alt"),
    8443:  (7,  "HTTPS-alt"),
    27017: (14, "MongoDB"),
}

_COMBOS: list[tuple[frozenset, int, str]] = [
    (frozenset({88, 389, 445}), 12, "DC combo (Kerberos+LDAP+SMB)"),
    (frozenset({1433, 445}),    10, "MSSQL+SMB — high-value DB"),
    (frozenset({5985, 445}),     6, "WinRM+SMB — full Windows foothold"),
    (frozenset({3389, 445}),     6, "RDP+SMB — graphical+file access"),
    (frozenset({80, 445}),       6, "HTTP+SMB — web+relay"),
    (frozenset({80, 443}),       3, "HTTP+HTTPS"),
    (frozenset({6379}),          8, "Redis — often unauth"),
    (frozenset({27017}),         8, "MongoDB — often unauth"),
    (frozenset({23}),           10, "Telnet — cleartext creds"),
]


def score_host(host: Host) -> tuple[int, list[str]]:
    """Return (score, [reason strings]) for a single host."""
    ports = set(host.open_ports)
    score = 0
    reasons: list[str] = []

    for p, (pts, label) in _PORT_SCORES.items():
        if p in ports:
            score += pts
            if pts >= 7:
                reasons.append(f"{label} (:{p})")

    for combo_ports, bonus, desc in _COMBOS:
        if combo_ports.issubset(ports):
            score += bonus
            reasons.append(desc)

    n = len(ports)
    if n > 15:
        score += 8
        reasons.append(f"{n} open ports")
    elif n > 8:
        score += 4

    return score, reasons


def rank_hosts(session: EnumSession) -> list[tuple]:
    """Return [(ip, host, score, reasons)] sorted by score descending."""
    ranked = []
    for ip, host in session.hosts.items():
        if host.open_ports:
            s, r = score_host(host)
            if s > 0:
                ranked.append((ip, host, s, r))
    return sorted(ranked, key=lambda x: x[2], reverse=True)


def score_host_final(host: "Host | None", session: EnumSession) -> tuple[int, list[str]]:
    """Post-focus score: base port score + bonuses from command history findings."""
    if host is None:
        return 0, []
    score, reasons = score_host(host)

    history = session.command_history
    outputs = " ".join(r.output for r in history)
    labels  = " ".join(r.label  for r in history)

    # Admin credentials found
    if any(c.success and c.is_admin for c in session.credentials):
        score += 30
        reasons.append("👑 Admin creds obtained")
    elif any(c.success for c in session.credentials):
        score += 15
        reasons.append("🔑 Valid creds found")

    # WebDAV executable upload
    if "SUCCEED" in outputs and any(
        ext in outputs for ext in ("php SUCCEED", "asp SUCCEED", "aspx SUCCEED", "jsp SUCCEED")
    ):
        score += 20
        reasons.append("🔴 WebDAV PUT RCE")

    # .git exposure
    if "git-dumper" in labels:
        score += 18
        reasons.append("🔴 .git exposed (dumped)")

    # LFI parameters
    if "LFI params" in labels:
        score += 10
        reasons.append("⚠ LFI params detected")

    # SNMP public community
    if any("snmp" in r.label.lower() and r.output.strip() and len(r.output) > 100
           for r in history):
        score += 8
        reasons.append("📡 SNMP public readable")

    # SMB relay candidate (already in base score via port, add if no signing)
    if not host.smb_signing:
        score += 6
        reasons.append("⚡ SMB relay candidate")

    # Vuln scan findings
    if any("vuln" in r.label.lower() and "VULNERABLE" in r.output for r in history):
        score += 12
        reasons.append("💥 Vuln scan findings")

    return score, reasons
