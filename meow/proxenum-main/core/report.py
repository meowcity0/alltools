from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from .models import EnumSession, Host
from .parsers import (parse_enum4linux, parse_nmap_vuln,
                      parse_whatweb, parse_curl_headers, parse_nxc_shares)
from .checklist import checklist_html, checklist_md

HIGH_VALUE_PORTS = {
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389,
    443, 445, 465, 587, 636, 1433, 1521, 3306, 3389, 5432,
    5985, 5986, 8080, 8443, 27017,
}
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}

_COPY_ICON = (
    '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
    '<path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25'
    " 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75"
    " 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z\"/>"
    '<path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75'
    " 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0"
    " 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0"
    ' 0-.25-.25Z"/></svg>'
)


class ReportGenerator:
    def __init__(self, console: Console, session: EnumSession,
                 focus_data: dict | None = None, mode: str = "scan"):
        self.console = console
        self.session = session
        self._focus_data: dict = focus_data or {}
        self._mode = mode

    def generate(self, output_dir: str = ".", quiet: bool = False,
                 filename: str | None = None) -> str:
        mode = self._mode  # "scan" or "drill"
        # Stable, predictable filename (drill.html / scan.html) so the report is
        # easy to find and so progressive re-renders overwrite the same file.
        if filename is None:
            filename = f"{mode}.html"
        out = Path(output_dir) / filename
        out.write_text(self._build(), encoding="utf-8")
        if not quiet:
            self.console.print()
            self.console.print(
                Panel(
                    f"[bold #7aab7a]Report:[/bold #7aab7a] [#c0c8d4]{out}[/#c0c8d4]",
                    border_style="#30363d",
                    padding=(0, 2),
                )
            )
        return str(out)

    # ------------------------------------------------------------------ build

    def _build(self) -> str:
        now = datetime.now()
        hosts = self.session.hosts
        creds = self.session.credentials
        successes = [c for c in creds if c.success]
        elapsed = now - self.session.started_at
        m, s = divmod(int(elapsed.total_seconds()), 60)
        relay_hosts = [h for h in hosts.values() if h.relay_candidate]

        subs = {
            "DOMAIN": self.session.domain,
            "DATE": now.strftime("%Y-%m-%d %H:%M"),
            "TOTAL_HOSTS": str(len(hosts)),
            "TOTAL_PORTS": str(sum(len(h.open_ports) for h in hosts.values())),
            "TOTAL_CREDS": str(len(successes)),
            "TOTAL_ADMIN": str(sum(1 for c in successes if c.is_admin)),
            "RELAY_COUNT": str(len(relay_hosts)),
            "DURATION": f"{m}m{s:02d}s",
            "CRED_CLASS": "success" if successes else "",
            "ADMIN_CLASS": "danger" if any(c.is_admin for c in successes) else "",
            "DOMAIN_BANNER": self._domain_banner(),
            "RELAY_BANNER": self._relay_banner(relay_hosts),
            "HOST_ROWS": self._host_rows_summary(),
            "HOST_DETAIL_ROWS": self._host_detail_rows(),
            "PORT_ROWS": self._port_rows(),
            "PORT_SUMMARY_ROWS": self._port_summary_rows(),
            "MD_PORT_SUMMARY": self._md_port_summary(),
            "CRED_ROWS": self._cred_rows(),
            "MATRIX_HTML": self._matrix_html(),
            "CHECKLIST_ITEMS": self._checklist_items(),
            "COMMAND_BLOCKS": self._command_blocks(),
            "MD_HOSTS": self._md_hosts(),
            "MD_PORTS": self._md_ports(),
            "MD_CREDS": self._md_creds(),
            "MD_MATRIX": self._md_matrix(),
            "MD_CHECKLIST": self._md_checklist(),
            "HTTP_LINKS": self._http_links_html(),
            "PRIORITY_ROWS": self._priority_rows(),
            "MD_PRIORITY": self._md_priority(),
            "FOCUS_NAV_ITEMS": self._focus_nav_items(),
            "FOCUS_SECTIONS": self._focus_sections(),
            "CRITICAL_HTML": self._critical_html(),
            "HEATMAP_HTML": self._heatmap_html(),
            "HOSTS_BLOCK_HTML": self._hosts_block_html(),
            "COPY_ICON": _COPY_ICON,
            "COPY_ICON_RAW": _COPY_ICON,
        }
        tpl = _load_template()
        for k, v in subs.items():
            tpl = tpl.replace(f"%%{k}%%", v)
        return tpl

    # ----------------------------------------------------------- html helpers

    def _hosts_block_html(self) -> str:
        lines = []
        for ip, h in sorted(self.session.hosts.items()):
            parts = [ip]
            if h.fqdn not in ("Unknown", ""):
                parts.append(h.fqdn)
            if h.hostname not in ("Unknown", "", h.fqdn):
                parts.append(h.hostname)
            if len(parts) > 1:
                lines.append("  ".join(parts))
        if not lines:
            return ""
        text = "\n".join(lines)
        esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            '<div class="card" style="margin-top:14px">'
            '<div class="card-header">'
            '<div class="card-title">/etc/hosts entries</div>'
            '<button class="copy-btn" onclick="copyPre(\'etc-hosts-block\')">%%COPY_ICON%%  Copy</button>'
            '</div>'
            f'<pre id="etc-hosts-block" style="font-size:12px;padding:10px 14px;'
            f'background:var(--bg-code);border-radius:6px;overflow-x:auto;'
            f'color:var(--accent-sage);margin:0">{esc}</pre>'
            '</div>'
        )

    def _domain_banner(self) -> str:
        if self.session.domain == "Unknown":
            return ""
        return (
            '<div class="domain-banner">'
            f"Domain detected: <strong>{self.session.domain}</strong>"
            "</div>"
        )

    def _relay_banner(self, relay_hosts: list) -> str:
        if not relay_hosts:
            return ""
        names = ", ".join(h.hostname for h in relay_hosts)
        return (
            '<div class="relay-banner">'
            f"⚡ {len(relay_hosts)} SMB relay candidate(s): {names} — signing disabled"
            "</div>"
        )

    @staticmethod
    def _port_color(port: int, svc: str) -> str:
        s = (svc or "").lower()
        if port in {88, 389, 636, 3268, 3269} or "ldap" in s or "kerberos" in s:
            return "port-cat-auth"
        if port in {445, 139, 135} or "smb" in s or "netbios" in s or "microsoft-ds" in s:
            return "port-cat-smb"
        if port in {3389, 5985, 5986, 23} or "rdp" in s or "winrm" in s or "ms-wbt" in s:
            return "port-cat-remote"
        if port in {80, 443, 8080, 8443, 8000, 8888} or "http" in s:
            return "port-cat-web"
        if port in {1433, 3306, 5432, 1521, 27017, 6379} or any(
            d in s for d in ("mysql", "mssql", "postgres", "oracle", "mongo", "redis")
        ):
            return "port-cat-db"
        if port in {25, 110, 143, 465, 587, 993, 995} or any(m in s for m in ("smtp", "imap", "pop")):
            return "port-cat-mail"
        if port in {21} or "ftp" in s:
            return "port-cat-ftp"
        if port in {22} or "ssh" in s:
            return "port-cat-ssh"
        if port in {53} or "domain" in s:
            return "port-cat-dns"
        return "port-tag"

    def _port_tags(self, host: Host) -> str:
        udp = getattr(host, "udp_ports", None) or {}
        if not host.open_ports and not udp:
            return '<span class="badge badge-muted">—</span>'
        tags = []
        for p, s in sorted(host.open_ports.items()):
            cls = self._port_color(p, s)
            tags.append(f'<span class="{cls}">{p}/{s}</span>')
        for p, s in sorted(udp.items()):
            tags.append(
                f'<span class="port-tag" style="opacity:.7;font-style:italic">{p}/udp</span>'
            )
        return f'<div class="port-list">{"".join(tags)}</div>'

    def _copy_btn(self, target_id: str) -> str:
        return (
            f'<button class="copy-btn" onclick="copyMd(\'{target_id}\')">'
            f"{_COPY_ICON} Copy Markdown</button>"
        )

    # --------------------------------------------------------- table sections

    def _host_rows_summary(self) -> str:
        rows = []
        for ip, h in self.session.hosts.items():
            signing = (
                '<span class="badge badge-muted">✓ On</span>'
                if h.smb_signing
                else '<span class="badge badge-danger">✗ Off</span>'
            )
            rows.append(
                f"<tr>"
                f'<td class="td-ip">{ip}</td>'
                f'<td class="td-hostname">{h.hostname}</td>'
                f'<td class="td-os">{h.fqdn}</td>'
                f'<td class="td-os">{h.os_info}</td>'
                f'<td class="td-domain">{h.domain}</td>'
                f"<td>{signing}</td>"
                f"<td>{self._port_tags(h)}</td>"
                f"</tr>"
            )
        return "\n".join(rows) or _no_data(7)

    def _host_detail_rows(self) -> str:
        rows = []
        for ip, h in self.session.hosts.items():
            signing = (
                '<span class="badge badge-muted">✓ On</span>'
                if h.smb_signing
                else '<span class="badge badge-danger">✗ Off</span>'
            )
            relay = (
                '<span class="badge badge-danger">⚡ Yes</span>'
                if h.relay_candidate
                else '<span class="badge badge-muted">—</span>'
            )
            rows.append(
                f"<tr>"
                f'<td class="td-ip">{ip}</td>'
                f'<td class="td-hostname">{h.hostname}</td>'
                f'<td class="td-os">{h.fqdn}</td>'
                f'<td class="td-os">{h.os_info}</td>'
                f'<td class="td-domain">{h.domain}</td>'
                f"<td>{signing}</td>"
                f"<td>{relay}</td>"
                f"</tr>"
            )
        return "\n".join(rows) or _no_data(7)

    def _port_rows(self) -> str:
        rows = []
        for ip, h in self.session.hosts.items():
            if not h.open_ports:
                continue
            rows.append(
                f"<tr>"
                f'<td class="td-hostname">{h.display_name}</td>'
                f'<td class="td-ip">{ip}</td>'
                f"<td>{self._port_tags(h)}</td>"
                f"</tr>"
            )
        return "\n".join(rows) or _no_data(3)

    def _cred_rows(self) -> str:
        rows = []
        for c in self.session.credentials:
            if not c.success:
                continue
            h = self.session.hosts.get(c.ip)
            name = h.display_name if h else c.ip
            admin = (
                '<span class="badge badge-gold">👑 Admin</span>'
                if c.is_admin
                else '<span class="badge badge-muted">—</span>'
            )
            if c.is_ntlm:
                secret_cell = (
                    f'<td><span class="badge badge-muted" title="{c.password}">'
                    f'NTLM {c.password[:16]}…</span></td>'
                )
            else:
                secret_cell = (
                    f'<td style="font-family:var(--font-mono);color:var(--accent-gold)">{c.password}</td>'
                )
            is_local = getattr(c, 'local_auth', False)
            if is_local:
                auth_badge = (
                    '<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                    'background:#c9a96e22;border:1px solid #c9a96e55;color:#c9a96e">LOCAL</span>'
                )
            else:
                auth_badge = (
                    '<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                    'background:#7aab7a22;border:1px solid #7aab7a55;color:#7aab7a">DOMAIN</span>'
                )
            rows.append(
                f"<tr>"
                f'<td><span class="badge badge-info">{c.protocol}</span></td>'
                f'<td class="td-hostname">{name}</td>'
                f'<td class="td-ip">{c.ip}</td>'
                f'<td style="font-family:var(--font-mono)">{c.username}</td>'
                f"{secret_cell}"
                f"<td>{auth_badge}</td>"
                f"<td>{admin}</td>"
                f"</tr>"
            )
        return "\n".join(rows) or _no_data(7)

    def _port_summary_rows(self) -> str:
        rows = []
        for ip, h in self.session.hosts.items():
            if not h.open_ports:
                continue
            ports = ", ".join(str(p) for p in sorted(h.open_ports.keys()))
            rows.append(
                f"<tr>"
                f'<td class="td-hostname">{h.display_name}</td>'
                f'<td class="td-ip">{ip}</td>'
                f'<td style="font-family:var(--font-mono);font-size:12px">{ports}</td>'
                f"</tr>"
            )
        return "\n".join(rows) or _no_data(3)

    def _matrix_html(self) -> str:
        hosts = list(self.session.hosts.values())
        if not hosts or not self.session.credentials:
            return '<p class="empty-msg">No credential data.</p>'

        pairs = sorted({(c.username, c.password) for c in self.session.credentials})
        rmap: dict[tuple, str] = {}
        for c in self.session.credentials:
            rmap[(c.username, c.password, c.ip)] = (
                "admin" if c.is_admin else ("success" if c.success else "fail")
            )

        heads = "".join(f'<th title="{h.ip}">{h.hostname[:10]}</th>' for h in hosts)
        rows = []
        for user, pwd in pairs:
            label = f"{user}:{pwd[:14]}{'…' if len(pwd) > 14 else ''}"
            cells = f'<td class="td-ip" style="font-size:11px">{label}</td>'
            for h in hosts:
                st = rmap.get((user, pwd, h.ip))
                if st == "admin":
                    cells += '<td class="cell-admin">👑</td>'
                elif st == "success":
                    cells += '<td class="cell-success">✓</td>'
                elif st == "fail":
                    cells += '<td class="cell-fail">✗</td>'
                else:
                    cells += '<td style="color:var(--text-muted)">—</td>'
            rows.append(f"<tr>{cells}</tr>")

        return (
            '<table class="matrix-table">'
            f"<thead><tr><th>Credential</th>{heads}</tr></thead>"
            f'<tbody>{"".join(rows)}</tbody>'
            "</table>"
        )

    def _checklist_items(self) -> str:
        # Static Japanese OSCP checklist (shared across all report modes).
        return checklist_html()

    def _gen_checklist(self) -> list[str]:
        items: list[str] = []
        hosts = list(self.session.hosts.values())
        items.append("✦ Confirm SOCKS proxy (chisel / ligolo) is stable")

        if self.session.domain != "Unknown":
            d = self.session.domain
            items += [
                f"✦ Add {d} DC entries to /etc/hosts",
                f"✦ Enumerate domain users: nxc smb [DC] --users",
                f"✦ Kerberoast: GetUserSPNs.py {d}/[user]:[pass]",
                f"✦ AS-REP Roast: GetNPUsers.py {d}/ -no-pass",
            ]

        relay = [h for h in hosts if h.relay_candidate]
        if relay:
            ips = ", ".join(h.ip for h in relay)
            items.append(f"✦ SMB relay (ntlmrelayx) against: {ips}")

        all_ports: set[int] = set()
        for h in hosts:
            all_ports |= set(h.open_ports)

        if all_ports & {80, 443, 8080, 8443}:
            items.append("✦ Web enum: feroxbuster / gobuster on HTTP(S)")
        if 21 in all_ports:
            items.append("✦ FTP: check anonymous login")
        if 3389 in all_ports:
            items.append("✦ RDP available — try xfreerdp with valid creds")
        if all_ports & {5985, 5986}:
            items.append("✦ WinRM — try evil-winrm with valid creds")
        if 1433 in all_ports:
            items.append("✦ MSSQL — check xp_cmdshell, linked servers")
        if 3306 in all_ports:
            items.append("✦ MySQL — enumerate databases")
        if 445 in all_ports:
            items.append("✦ SMB shares: nxc smb [IP] --shares")
            items.append("✦ Anonymous access: smbclient -L //[IP]/ -N")

        successes = [c for c in self.session.credentials if c.success]
        if successes:
            items.append(f"✦ {len(successes)} cred(s) confirmed — attempt lateral movement")
        if any(c.is_admin for c in successes):
            items.append("✦ Admin creds — dump SAM/NTDS: secretsdump.py")

        items.append("✦ Check shares / configs for cleartext passwords")
        items.append("✦ Document pivot paths for OSCP report")
        return items

    def _command_blocks(self) -> str:
        if not self.session.command_history:
            return '<p class="empty-msg">No commands recorded.</p>'
        blocks = []
        for i, rec in enumerate(self.session.command_history):
            ts = rec.timestamp.strftime("%H:%M:%S")
            rc = (
                '<span class="badge badge-success">rc=0</span>'
                if rec.return_code == 0
                else f'<span class="badge badge-danger">rc={rec.return_code}</span>'
            )
            safe_out = (
                rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            # embed raw output in a hidden textarea for reliable copying
            raw_id = f"cmd-raw-{i}"
            blocks.append(
                '<div class="card">'
                '<div class="code-header">'
                f'<span style="color:var(--accent-gold)">{rec.label or "Command"}</span>'
                f'<span style="display:flex;gap:8px;align-items:center">{rc}'
                f'<span style="color:var(--accent-gold)">{rec.duration:.1f}s</span>'
                f'<span style="color:var(--text-muted)">{ts}</span>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{raw_id}\').value,this)">'
                f'{_COPY_ICON} Copy Output</button>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{raw_id}\').dataset.cmd,this)">'
                f'{_COPY_ICON} Copy Command</button>'
                "</span></div>"
                f'<div class="code-block cmd-line">$ {rec.command}</div>'
                f'<textarea id="{raw_id}" style="display:none"'
                f' data-cmd="{rec.command.replace(chr(34), chr(39))}">'
                f'{rec.output}</textarea>'
                f'<div class="code-block output-block"><code>{safe_out or "(no output)"}</code></div>'
                "</div>"
            )
        return "\n".join(blocks)

    # --------------------------------------------------------- markdown exports

    def _md_hosts(self) -> str:
        lines = [
            "| IP | Hostname | FQDN | OS | Domain | SMB Signing |",
            "|----|----------|------|----|--------|-------------|",
        ]
        for ip, h in self.session.hosts.items():
            lines.append(
                f"| {ip} | {h.hostname} | {h.fqdn} | {h.os_info} | {h.domain} | {'✓' if h.smb_signing else '✗'} |"
            )
        return "\n".join(lines)

    def _md_ports(self) -> str:
        lines = ["| Host | IP | TCP Ports | UDP Ports |", "|------|----|-----------|-----------|"]
        for ip, h in self.session.hosts.items():
            udp = getattr(h, "udp_ports", None) or {}
            if h.open_ports or udp:
                tcp = ", ".join(f"{p}/{s}" for p, s in sorted(h.open_ports.items()))
                udp_str = ", ".join(str(p) for p in sorted(udp.keys()))
                lines.append(f"| {h.display_name} | {ip} | {tcp or '—'} | {udp_str or '—'} |")
        return "\n".join(lines)

    def _md_port_summary(self) -> str:
        lines = ["| Host | IP | TCP | UDP |", "|------|----|-----|-----|"]
        for ip, h in self.session.hosts.items():
            udp = getattr(h, "udp_ports", None) or {}
            if h.open_ports or udp:
                tcp = ", ".join(str(p) for p in sorted(h.open_ports.keys()))
                udp_str = ", ".join(str(p) for p in sorted(udp.keys()))
                lines.append(f"| {h.display_name} | {ip} | {tcp or '—'} | {udp_str or '—'} |")
        return "\n".join(lines)

    def _md_creds(self) -> str:
        lines = [
            "| Protocol | Host | Username | Secret | Admin |",
            "|----------|------|----------|--------|-------|",
        ]
        for c in self.session.credentials:
            if c.success:
                h = self.session.hosts.get(c.ip)
                name = h.display_name if h else c.ip
                secret = f"[NTLM] {c.password}" if c.is_ntlm else c.password
                lines.append(
                    f"| {c.protocol} | {name} | {c.username} | {secret} | {'👑' if c.is_admin else '—'} |"
                )
        return "\n".join(lines)

    def _md_matrix(self) -> str:
        hosts = list(self.session.hosts.values())
        if not hosts or not self.session.credentials:
            return "No credential data."
        pairs = sorted({(c.username, c.password) for c in self.session.credentials})
        rmap = {
            (c.username, c.password, c.ip): ("👑" if c.is_admin else ("✓" if c.success else "✗"))
            for c in self.session.credentials
        }
        lines = [
            "| Credential | " + " | ".join(h.hostname for h in hosts) + " |",
            "|---|" + "---|" * len(hosts),
        ]
        for user, pwd in pairs:
            cells = " | ".join(rmap.get((user, pwd, h.ip), "—") for h in hosts)
            lines.append(f"| {user}:{pwd} | {cells} |")
        return "\n".join(lines)

    def _md_checklist(self) -> str:
        return checklist_md()

    # ─── HTTP links ────────────────────────────────────────────────────────

    def _http_links_html(self) -> str:
        links = []
        for ip, host in self.session.hosts.items():
            for port, svc in sorted(host.open_ports.items()):
                svc_l = svc.lower()
                if port not in HTTP_PORTS and "http" not in svc_l:
                    continue
                is_https = port in {443, 8443} or "ssl" in svc_l or svc_l == "https"
                scheme = "https" if is_https else "http"
                url = f"{scheme}://{ip}" + (f":{port}" if port not in {80, 443} else "")
                label = host.display_name if host.display_name != ip else ip
                links.append(
                    f'<a href="{url}" target="_blank" class="http-link">'
                    f'[{label}] {url}</a>'
                )
        if not links:
            return '<p class="empty-msg">No HTTP services found.</p>'
        return "\n".join(links)

    # ─── priority targets ──────────────────────────────────────────────────

    def _priority_rows(self) -> str:
        from .scoring import rank_hosts
        ranked = rank_hosts(self.session)
        if not ranked:
            return _no_data(5)
        medals = ["🥇", "🥈", "🥉"]
        rows = []
        for i, (ip, host, score, reasons) in enumerate(ranked[:10], 1):
            badge_cls = "badge-danger" if score >= 40 else "badge-warning" if score >= 20 else "badge-info"
            medal = medals[i - 1] if i <= 3 else f"#{i}"
            desc = " &nbsp;·&nbsp; ".join(reasons[:3]) or "—"
            rows.append(
                f"<tr>"
                f'<td style="text-align:center;font-size:15px">{medal}</td>'
                f'<td class="td-ip">{ip}</td>'
                f'<td class="td-hostname">{host.display_name}</td>'
                f'<td><span class="badge {badge_cls}">{score} pts</span></td>'
                f'<td style="font-size:12px;color:var(--text-muted)">{desc}</td>'
                f"</tr>"
            )
        return "\n".join(rows)

    def _md_priority(self) -> str:
        from .scoring import rank_hosts
        ranked = rank_hosts(self.session)
        lines = ["| # | IP | Host | Score | Reasons |", "|---|----|----|-----|---------|"]
        for i, (ip, host, score, reasons) in enumerate(ranked[:10], 1):
            r = ", ".join(reasons[:3]) or "—"
            lines.append(f"| {i} | {ip} | {host.display_name} | {score} | {r} |")
        return "\n".join(lines)

    # ─── drill focus sections ──────────────────────────────────────────────

    def _focus_nav_items(self) -> str:
        if not self._focus_data:
            return ""
        items = []
        for ip, fsession in self._focus_data.items():
            host = self.session.hosts.get(ip) or fsession.hosts.get(ip)
            name = host.display_name if host else ip
            sid = f"focus-{ip.replace('.', '-')}"
            disp = host.display_name if (host and host.display_name != ip) else ip.replace(".", "_")
            items.append(
                f'<button class="nav-item" onclick="show(\'{sid}\',this)">◈ {name}</button>'
                f'<a href="./{disp}/report.html" target="_blank" '
                f'style="display:block;padding:2px 8px 8px;font-size:10px;'
                f'color:var(--text-muted);text-decoration:none;'
                f'transition:color .15s" onmouseover="this.style.color=\'var(--accent-gold)\'" '
                f'onmouseout="this.style.color=\'var(--text-muted)\'">↗ detail report</a>'
            )
        return "\n".join(items)

    def _focus_sections(self) -> str:
        if not self._focus_data:
            return ""
        sections = []
        for ip, fsession in self._focus_data.items():
            host = fsession.hosts.get(ip) or self.session.hosts.get(ip)
            sid = f"focus-{ip.replace('.', '-')}"
            name = host.display_name if host else ip
            disp = host.display_name if (host and host.display_name != ip) else ip.replace(".", "_")
            tcp_rows = self._focus_port_rows(fsession, ip)
            cmd_blocks = self._focus_cmd_blocks(fsession, ip)
            e4l_html = self._focus_enum4linux_html(fsession)
            vuln_html = self._focus_vuln_html(fsession)
            udp_rows = self._focus_udp_rows(fsession, ip)
            sections.append(
                f'<div class="section" id="section-{sid}">'
                f'<div class="section-header">'
                f'<div class="section-title">◈ Focus: {name}</div>'
                f'<div class="section-desc" style="display:flex;align-items:center;gap:10px">'
                f'{ip} — deep enumeration'
                f'<a href="./{disp}/report.html" target="_blank" class="copy-btn" '
                f'style="text-decoration:none;font-size:11px">↗ Full Detail</a>'
                f'</div>'
                f'</div>'
                f'<div class="card">'
                f'<div class="card-header"><div class="card-title">TCP Ports</div></div>'
                f'<div class="table-wrapper"><table>'
                f'<thead><tr><th>Port</th><th>Service</th></tr></thead>'
                f'<tbody>{tcp_rows}</tbody></table></div></div>'
                + (f'<div class="card"><div class="card-header"><div class="card-title">'
                   f'UDP Ports (top-20)</div></div>'
                   f'<div class="table-wrapper"><table>'
                   f'<thead><tr><th>Port</th><th>Service</th></tr></thead>'
                   f'<tbody>{udp_rows}</tbody></table></div></div>' if udp_rows else "")
                + (f'<div class="card"><div class="card-header"><div class="card-title">'
                   f'Vulnerability Scan</div></div>{vuln_html}</div>' if vuln_html else "")
                + (f'<div class="card"><div class="card-header"><div class="card-title">'
                   f'SMB / enum4linux-ng (parsed)</div></div>{e4l_html}</div>' if e4l_html else "")
                + f'<div class="card"><div class="card-header">'
                  f'<div class="card-title">Command Log</div></div>'
                  f'<div style="padding:0 2px">{cmd_blocks}</div></div>'
                + f'</div>'
            )

        # Final attack surface ranking (post-focus score)
        if self._focus_data:
            from .scoring import rank_hosts
            ranking_rows = []
            focus_hosts_session = []
            for ip, fsession in self._focus_data.items():
                host = fsession.hosts.get(ip) or self.session.hosts.get(ip)
                focus_hosts_session.append((ip, host, fsession))

            # Use existing rank_hosts on a per-session basis for scores
            for rank_i, (ip, host, fsession) in enumerate(focus_hosts_session, 1):
                ranked = rank_hosts(fsession)
                if ranked:
                    _, _, score, reasons = ranked[0]
                else:
                    score, reasons = 0, []
                name = host.display_name if host else ip
                badge_cls = "badge-danger" if score >= 40 else "badge-warning" if score >= 20 else "badge-info"
                medal = ["🥇", "🥈", "🥉"][rank_i - 1] if rank_i <= 3 else f"#{rank_i}"
                desc = " &nbsp;·&nbsp; ".join(reasons[:3]) or "—"
                # Add note about commands run
                cmd_count = len(fsession.command_history)
                ranking_rows.append(
                    f"<tr>"
                    f'<td style="text-align:center;font-size:15px">{medal}</td>'
                    f'<td class="td-ip">{ip}</td>'
                    f'<td class="td-hostname">{name}</td>'
                    f'<td><span class="badge {badge_cls}">{score} pts</span></td>'
                    f'<td style="font-size:11px;color:var(--text-muted)">{cmd_count} cmds run</td>'
                    f'<td style="font-size:12px;color:var(--text-muted)">{desc}</td>'
                    f"</tr>"
                )

            if ranking_rows:
                ranking_html = (
                    '<div class="section" id="section-final-ranking">'
                    '<div class="section-header">'
                    '<div class="section-title">Final Attack Surface Ranking</div>'
                    '<div class="section-desc">post-focus score — accumulated enumeration data</div>'
                    '</div>'
                    '<div class="card">'
                    '<div class="table-wrapper"><table>'
                    '<thead><tr><th>#</th><th>IP</th><th>Host</th><th>Score</th><th>Commands</th><th>Reasons</th></tr></thead>'
                    f'<tbody>{"".join(ranking_rows)}</tbody></table></div></div>'
                    '</div>'
                )
                sections.append(ranking_html)

        return "\n".join(sections)

    def _focus_port_rows(self, fsession: EnumSession, ip: str) -> str:
        host = fsession.hosts.get(ip)
        if not host or not host.open_ports:
            return _no_data(3)
        rows = []
        for port, svc in sorted(host.open_ports.items()):
            cls = "port-tag high-value" if port in HIGH_VALUE_PORTS else "port-tag"
            rows.append(
                f"<tr>"
                f'<td><span class="{cls}">{port}/tcp</span></td>'
                f'<td style="color:var(--text-secondary)">{svc}</td>'
                f"<td></td></tr>"
            )
        return "\n".join(rows) or _no_data(3)

    def _focus_udp_rows(self, fsession: EnumSession, ip: str) -> str:
        host = fsession.hosts.get(ip)
        if not host or not host.udp_ports:
            return ""
        rows = []
        for port, svc in sorted(host.udp_ports.items()):
            cls = "port-tag high-value" if port in HIGH_VALUE_PORTS else "port-tag"
            rows.append(
                f"<tr>"
                f'<td><span class="{cls}">{port}/udp</span></td>'
                f'<td style="color:var(--text-secondary)">{svc}</td>'
                f"</tr>"
            )
        return "\n".join(rows)

    def _focus_enum4linux_html(self, fsession: EnumSession) -> str:
        rec = next((r for r in fsession.command_history if "enum4linux-ng" in r.command), None)
        if not rec or not rec.output.strip():
            return ""
        parsed = parse_enum4linux(rec.output)
        parts = []
        if parsed.users:
            rows = "".join(f"<tr><td>{u}</td></tr>" for u in parsed.users)
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Users ({len(parsed.users)})</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Username</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if parsed.shares:
            rows = "".join(
                f"<tr><td style='font-family:var(--font-mono)'>{n}</td><td>{r}</td></tr>"
                for n, r in parsed.shares
            )
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Shares ({len(parsed.shares)})</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Share</th><th>Remark</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if parsed.password_policy:
            rows = "".join(
                f"<tr><td>{k}</td><td style='font-family:var(--font-mono)'>{v}</td></tr>"
                for k, v in parsed.password_policy.items()
            )
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Password Policy</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if not parts:
            return ""
        safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        raw_id = f"e4l-raw-{id(rec)}"
        return (
            "".join(parts)
            + f'<details style="margin-top:8px">'
            + f'<summary style="cursor:pointer;color:var(--text-muted);font-size:12px">Raw output</summary>'
            + f'<div class="code-block output-block" style="margin-top:6px"><code>{safe}</code></div>'
            + f'</details>'
        )

    def _focus_vuln_html(self, fsession: EnumSession) -> str:
        rec = next((r for r in fsession.command_history if "vuln" in r.label.lower()), None)
        if not rec or not rec.output.strip():
            return ""
        findings = parse_nmap_vuln(rec.output)
        if not findings:
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return f'<p class="empty-msg">No vulnerabilities detected.</p>'
        rows = "".join(
            f"<tr>"
            f'<td><span class="port-tag high-value">{f.port}/tcp</span></td>'
            f'<td style="font-family:var(--font-mono);color:var(--danger)">{f.script}</td>'
            f'<td style="font-size:12px">{f.detail[:200]}</td>'
            f"</tr>"
            for f in findings
        )
        return (
            f'<div class="table-wrapper"><table>'
            f'<thead><tr><th>Port</th><th>Script</th><th>Detail</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _critical_html(self) -> str:
        parts: list[str] = []
        all_sessions = [self.session] + list(self._focus_data.values())

        # Accessible shares (READ or WRITE)
        share_rows: list[str] = []
        for sess in all_sessions:
            for rec in sess.command_history:
                if "--shares" not in rec.command or not rec.output.strip():
                    continue
                ip_m = __import__("re").search(r"(\d+\.\d+\.\d+\.\d+)", rec.command)
                src_ip = ip_m.group(1) if ip_m else "?"
                for name, perms, remark in parse_nxc_shares(rec.output):
                    badge = "badge-danger" if "WRITE" in perms else "badge-warning"
                    share_rows.append(
                        f"<tr><td class='td-ip'>{src_ip}</td>"
                        f"<td style='font-family:var(--font-mono)'>{name}</td>"
                        f"<td><span class='badge {badge}'>{perms}</span></td>"
                        f"<td style='color:var(--text-muted);font-size:12px'>{remark}</td></tr>"
                    )
        if share_rows:
            parts.append(
                '<div class="card">'
                '<div class="card-header"><div class="card-title">Accessible SMB Shares</div></div>'
                '<div class="table-wrapper"><table>'
                '<thead><tr><th>IP</th><th>Share</th><th>Permission</th><th>Remark</th></tr></thead>'
                f'<tbody>{"".join(share_rows)}</tbody></table></div></div>'
            )

        # Vuln findings
        vuln_rows: list[str] = []
        for sess in all_sessions:
            for rec in sess.command_history:
                if "vuln" not in rec.label.lower() or not rec.output.strip():
                    continue
                ip_m = __import__("re").search(r"(\d+\.\d+\.\d+\.\d+)", rec.command)
                src_ip = ip_m.group(1) if ip_m else "?"
                for f in parse_nmap_vuln(rec.output):
                    vuln_rows.append(
                        f"<tr><td class='td-ip'>{src_ip}</td>"
                        f"<td><span class='port-tag high-value'>{f.port}/tcp</span></td>"
                        f"<td style='font-family:var(--font-mono);color:var(--danger)'>{f.script}</td>"
                        f"<td style='font-size:12px'>{f.detail[:200]}</td></tr>"
                    )
        if vuln_rows:
            parts.append(
                '<div class="card">'
                '<div class="card-header"><div class="card-title">Vulnerability Findings</div></div>'
                '<div class="table-wrapper"><table>'
                '<thead><tr><th>IP</th><th>Port</th><th>Script</th><th>Detail</th></tr></thead>'
                f'<tbody>{"".join(vuln_rows)}</tbody></table></div></div>'
            )

        # Anonymous users (LDAP/SMB)
        user_rows: list[str] = []
        for sess in all_sessions:
            for rec in sess.command_history:
                if not any(k in rec.label.lower() for k in ("ldap anon", "smb users", "enum4linux")):
                    continue
                parsed = parse_enum4linux(rec.output)
                ip_m = __import__("re").search(r"(\d+\.\d+\.\d+\.\d+)", rec.command)
                src_ip = ip_m.group(1) if ip_m else "?"
                for u in parsed.users:
                    user_rows.append(
                        f"<tr><td class='td-ip'>{src_ip}</td>"
                        f"<td style='font-family:var(--font-mono)'>{u}</td>"
                        f"<td style='color:var(--text-muted);font-size:12px'>{rec.label}</td></tr>"
                    )
        if user_rows:
            parts.append(
                '<div class="card">'
                '<div class="card-header"><div class="card-title">Anonymous User Enumeration</div></div>'
                '<div class="table-wrapper"><table>'
                '<thead><tr><th>IP</th><th>Username</th><th>Source</th></tr></thead>'
                f'<tbody>{"".join(user_rows)}</tbody></table></div></div>'
            )

        # Unauthenticated / anonymous service access
        unauth_rows = _extract_unauth_rows(
            [r for s in all_sessions for r in s.command_history]
        )
        if unauth_rows:
            parts.append(
                '<div class="card">'
                '<div class="card-header"><div class="card-title">'
                '🔓 Unauthenticated Access</div></div>'
                '<div class="table-wrapper"><table>'
                '<thead><tr><th>IP</th><th>Service</th><th>Finding</th></tr></thead>'
                f'<tbody>{"".join(unauth_rows)}</tbody></table></div></div>'
            )

        if not parts:
            return '<div class="card"><p class="empty-msg">No critical findings detected.</p></div>'
        return "\n".join(parts)

    def _heatmap_html(self) -> str:
        hosts = list(self.session.hosts.values())
        if not hosts:
            return '<div class="card"><p class="empty-msg">No hosts.</p></div>'

        # Columns: commonly targeted ports in fixed order
        COLUMNS = [
            (22, "SSH", "#58a6ff"),
            (21, "FTP", "#58a6ff"),
            (25, "SMTP", "#8b7aa8"),
            (80, "HTTP", "#56d364"),
            (443, "HTTPS", "#56d364"),
            (445, "SMB", "#e3b341"),
            (139, "NB", "#e3b341"),
            (389, "LDAP", "#7aab7a"),
            (636, "LDAPS", "#7aab7a"),
            (88, "KRB", "#7aab7a"),
            (3389, "RDP", "#f85149"),
            (5985, "WRM", "#f85149"),
            (5986, "WRMS", "#f85149"),
            (1433, "MSSQL", "#c9a96e"),
            (3306, "MySQL", "#c9a96e"),
            (5432, "PG", "#c9a96e"),
            (6379, "Redis", "#c9a96e"),
            (8080, "HTTP*", "#56d364"),
            (8443, "HTTPS*", "#56d364"),
        ]

        active = [(p, lbl, col) for p, lbl, col in COLUMNS
                  if any(p in h.open_ports for h in hosts)]
        if not active:
            return '<div class="card"><p class="empty-msg">No port data for heatmap.</p></div>'

        heads = "".join(
            f'<th style="font-size:10px;padding:4px 8px;color:{col};'
            f'white-space:nowrap;text-align:center">'
            f'{lbl} <span style="color:var(--text-muted);font-size:9px">({p})</span></th>'
            for p, lbl, col in active
        )
        HTTP_PORTS_SET = {80, 443, 8080, 8443}
        rows_html: list[str] = []
        for host in hosts:
            cells = (
                f'<td class="td-ip" style="font-size:11px;white-space:nowrap">'
                f'{host.ip}<br><span style="color:var(--text-muted);font-size:10px">'
                f'{host.hostname}</span></td>'
            )
            for port, lbl, col in active:
                if port in host.open_ports:
                    svc = host.open_ports[port]
                    style = (
                        f"text-align:center;background:linear-gradient(135deg,"
                        f"{col}22,{col}44);border:1px solid {col}66;border-radius:4px;"
                        f"font-size:12px;color:{col};font-weight:700;padding:5px 4px"
                    )
                    if port in HTTP_PORTS_SET:
                        scheme = "https" if port in {443, 8443} else "http"
                        url = f"{scheme}://{host.ip}" + (f":{port}" if port not in {80, 443} else "")
                        cells += (
                            f'<td style="{style};cursor:pointer" title="{url}"'
                            f' onclick="window.open(\'{url}\',\'_blank\')">●</td>'
                        )
                    else:
                        cells += f'<td style="{style}" title="{svc}">●</td>'
                else:
                    cells += '<td style="text-align:center;color:var(--border);font-size:10px">·</td>'
            rows_html.append(f"<tr>{cells}</tr>")

        chips = self._port_chips_html(hosts)

        return (
            '<div class="card">'
            '<div class="card-header"><div class="card-title">Port Heatmap'
            ' <span style="font-size:11px;color:var(--text-muted);font-weight:400">'
            '— HTTP/HTTPS cells are clickable</span></div></div>'
            '<div style="overflow-x:auto">'
            '<table style="border-collapse:separate;border-spacing:3px;min-width:max-content">'
            f'<thead><tr><th style="text-align:left;font-size:11px;padding:4px 8px">Host</th>'
            f'{heads}</tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody>'
            '</table></div></div>'
            + chips
        )

    def _port_chips_html(self, hosts: list) -> str:
        """Per-host port chips — replaces the old SVG scatter plot."""
        has_any = any(h.open_ports for h in hosts)
        if not has_any:
            return ""

        _CAT_COL = {
            "port-cat-web": "#58a6ff", "port-cat-smb": "#e3b341",
            "port-cat-remote": "#f85149", "port-cat-auth": "#7aab7a",
            "port-cat-db": "#8b7aa8", "port-cat-mail": "#c9a96e",
            "port-cat-ssh": "#56d364", "port-cat-ftp": "#c9a96e",
            "port-cat-dns": "#56d364", "port-tag": "#58a6ff",
        }

        rows = []
        for h in hosts:
            udp_ports = getattr(h, "udp_ports", None) or {}
            if not h.open_ports and not udp_ports:
                continue
            chips = []
            for port, svc in sorted(h.open_ports.items()):
                col = _CAT_COL.get(self._port_color(port, svc), "#58a6ff")
                label = f"{port}" if not svc or svc == "unknown" else f"{port}/{svc}"
                chip = (
                    f'<span style="display:inline-block;font-size:11px;padding:2px 7px;'
                    f'margin:2px;border-radius:12px;background:{col}1a;border:1px solid {col}55;'
                    f'color:{col};font-family:monospace;white-space:nowrap">{label}</span>'
                )
                chips.append(chip)
            for port, svc in sorted(udp_ports.items()):
                label = f"{port}/udp"
                chip = (
                    f'<span style="display:inline-block;font-size:11px;padding:2px 7px;'
                    f'margin:2px;border-radius:12px;background:#56d36415;border:1px solid #56d36440;'
                    f'color:#56d364;font-family:monospace;white-space:nowrap;opacity:.8">{label}</span>'
                )
                chips.append(chip)
            label_cell = (
                f'<span style="display:inline-block;min-width:110px;font-size:11px;'
                f'color:var(--text-muted);vertical-align:top;padding-top:4px;'
                f'font-family:monospace">{h.ip}</span>'
            )
            rows.append(
                f'<div style="padding:4px 0;border-bottom:1px solid var(--border)">'
                f'{label_cell}{"".join(chips)}</div>'
            )
        if not rows:
            return ""
        return (
            '<div class="card" style="margin-top:14px">'
            '<div class="card-header"><div class="card-title">All Open Ports</div></div>'
            f'<div style="padding:8px 12px">{"".join(rows)}</div></div>'
        )

    def _focus_cmd_blocks(self, fsession: EnumSession, ip: str) -> str:
        if not fsession.command_history:
            return '<p class="empty-msg">No commands recorded.</p>'
        blocks = []
        for i, rec in enumerate(fsession.command_history):
            ts = rec.timestamp.strftime("%H:%M:%S")
            rc = (
                '<span class="badge badge-success">rc=0</span>'
                if rec.return_code == 0
                else f'<span class="badge badge-danger">rc={rec.return_code}</span>'
            )
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            raw_id = f"focus-cmd-{ip.replace('.','_')}-{i}"
            blocks.append(
                '<div style="margin-bottom:12px;border:1px solid var(--border);border-radius:8px">'
                '<div class="code-header">'
                f'<span style="color:var(--accent-gold)">{rec.label or "Command"}</span>'
                f'<span style="display:flex;gap:8px;align-items:center">{rc}'
                f'<span style="color:var(--text-muted)">{ts}</span>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{raw_id}\').value,this)">'
                f'{_COPY_ICON} Copy Output</button>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{raw_id}\').dataset.cmd,this)">'
                f'{_COPY_ICON} Copy Command</button>'
                f'</span></div>'
                f'<div class="code-block cmd-line">$ {rec.command}</div>'
                f'<textarea id="{raw_id}" style="display:none" data-cmd="{rec.command.replace(chr(34), chr(39))}">'
                f'{rec.output}</textarea>'
                f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>'
                '</div>'
            )
        return "\n".join(blocks)


# ──────────────────────────────────────────────────────── FocusReport

class FocusReport:
    """Standalone HTML report for a single focus/drill target."""

    def __init__(self, console: Console, session: EnumSession, ip: str):
        self.console = console
        self.session = session
        self.ip = ip
        self._out_dir: str = "."

    def _disp(self) -> str:
        host = self.session.hosts.get(self.ip)
        return (host.display_name if host and host.display_name != self.ip
                else self.ip.replace(".", "_"))

    def _detail_href(self) -> str:
        """Relative href to the host's nmap detail.html, correct for both the
        cwd-rooted focus report and the host-dir-rooted drill report."""
        disp = self._disp()
        try:
            same = Path(self._out_dir).resolve() == Path(disp).resolve()
        except Exception:
            same = False
        return "./detail.html" if same else f"./{disp}/detail.html"

    def generate(self, output_dir: str = ".", filename: str = "focus.html",
                 quiet: bool = False) -> str:
        # Record where the report lands so relative links (detail.html, output
        # tree) resolve correctly whether the report is written at the cwd
        # (focus mode → ./focus.html) or inside the host dir (drill → DC01/report.html).
        self._out_dir = output_dir
        out = Path(output_dir) / filename
        out.write_text(self._build(), encoding="utf-8")
        if not quiet:
            self.console.print(
                Panel(
                    f"[bold #c9a96e]Focus Report:[/bold #c9a96e] [#c0c8d4]{out}[/#c0c8d4]",
                    border_style="#c9a96e",
                    padding=(0, 2),
                )
            )
        return str(out)

    def _build(self) -> str:
        host = self.session.hosts.get(self.ip)
        name = host.display_name if host else self.ip
        now = datetime.now()
        elapsed = now - self.session.started_at
        m, s = divmod(int(elapsed.total_seconds()), 60)
        disp = self._disp()
        detail_card_path = self._detail_href()

        # Gather stats for the header bar
        tcp_count = len(host.open_ports) if host else 0
        udp_count = len(host.udp_ports) if host else 0
        cmd_count = len(self.session.command_history)
        sploits = sum(
            len([ln for ln in r.output.splitlines()
                 if "|" in ln and "Title" not in ln and "---" not in ln])
            for r in self.session.command_history
            if "searchsploit" in r.label.lower()
        )
        vuln_hits = sum(
            1 for r in self.session.command_history
            if "vuln" in r.label.lower() and "VULNERABLE" in r.output
        )
        cred_count = sum(1 for c in self.session.credentials if c.success)

        tcp_rows = self._tcp_rows(host)
        e4l_html = self._enum4linux_html()
        vuln_html = self._vuln_html()
        udp_html  = self._udp_html()
        http_html = self._http_html()
        cmd_blocks = self._cmd_blocks()

        # Build markdown port table for copy button
        _md_lines = ["| Port | Protocol | Service |", "|------|----------|---------|"]
        if host:
            for _p, _s in sorted(host.open_ports.items()):
                _md_lines.append(f"| {_p} | tcp | {_s} |")
            for _p, _s in sorted((host.udp_ports or {}).items()):
                _md_lines.append(f"| {_p} | udp | {_s} |")
        _md_ports_esc = "\n".join(_md_lines).replace("&", "&amp;").replace("<", "&lt;")
        tcp_section_content = (
            f'<div class="card-header" style="padding:10px 16px 8px;border-bottom:'
            f'1px solid var(--border);display:flex;align-items:center;justify-content:space-between">'
            f'<div class="card-title">Open Ports</div>'
            f'<button class="copy-btn" onclick="copyMd(\'focus-ports\')">📋 Copy Markdown</button>'
            f'</div>'
            f'<div class="table-wrapper"><table>'
            f'<thead><tr><th>Port</th><th>Service</th></tr></thead>'
            f'<tbody>{tcp_rows}</tbody></table></div>'
            f'<pre id="focus-ports" style="display:none">{_md_ports_esc}</pre>'
        )

        tpl = (Path(__file__).parent / "template.html").read_text(encoding="utf-8")
        css_match = __import__("re").search(r"<style>(.*?)</style>", tpl, __import__("re").S)
        css = f"<style>{css_match.group(1)}</style>" if css_match else ""
        js_match = __import__("re").search(r"<script>(.*?)</script>", tpl, __import__("re").S)
        js = f"<script>{js_match.group(1)}</script>" if js_match else ""

        critical_html = self._focus_critical_html()
        exec_graph_html = self._exec_graph_html()
        snmp_html = self._snmp_html()
        udp_note = f" · {udp_count} UDP" if udp_count else ""

        # Stats grid — same card style as scan report
        def _stat(value, label, cls=""):
            return (
                f'<div class="stat-card{" " + cls if cls else ""}">'
                f'<div class="stat-value">{value}</div>'
                f'<div class="stat-label">{label}</div>'
                f'</div>'
            )

        stats_html = (
            '<div class="stats-grid">'
            + _stat(tcp_count, "TCP Ports", "info" if tcp_count else "")
            + _stat(udp_count, "UDP Ports")
            + _stat(cmd_count, "Commands Run")
            + _stat(sploits, "Sploit Hits", "danger" if sploits else "")
            + _stat(vuln_hits, "Vuln Findings", "danger" if vuln_hits else "")
            + _stat(cred_count, "Valid Creds", "success" if cred_count else "")
            + '</div>'
        )

        # Port chips summary (inline for the overview section)
        port_chips = ""
        if host and host.open_ports:
            chips = []
            for p, svc in sorted(host.open_ports.items()):
                col = "#c9a96e" if p in HIGH_VALUE_PORTS else "#58a6ff"
                chips.append(
                    f'<span style="display:inline-block;font-family:monospace;font-size:11px;'
                    f'padding:2px 7px;margin:2px;border-radius:12px;'
                    f'background:{col}18;border:1px solid {col}44;color:{col}">'
                    f'{p}/{svc}</span>'
                )
            port_chips = (
                '<div class="card" style="margin-top:0">'
                '<div class="card-header"><div class="card-title">Open Ports</div></div>'
                f'<div style="padding:4px 6px">{"".join(chips)}</div>'
                '</div>'
            )
            # /etc/hosts helper
            host_entry = self.ip
            if host.hostname not in ("Unknown", ""):
                host_entry += f"  {host.hostname}"
            if host.fqdn not in ("Unknown", "", host.hostname):
                host_entry += f"  {host.fqdn}"
            esc_entry = host_entry.replace("&", "&amp;").replace("<", "&lt;")
            port_chips += (
                '<div class="card">'
                '<div class="card-header">'
                '<div class="card-title">/etc/hosts</div>'
                f'<button class="copy-btn" onclick="copyText(\'{esc_entry}\',this)">'
                f'{_COPY_ICON} Copy</button>'
                '</div>'
                f'<pre style="font-size:12px;padding:8px 12px;background:var(--bg-code,#0d1117);'
                f'border-radius:6px;color:var(--accent-sage);margin:0">{esc_entry}</pre>'
                '</div>'
            )

        # Domain / SMB info card
        info_parts = []
        if self.session.domain not in ("Unknown", ""):
            info_parts.append(f'<span style="color:var(--accent-sage)">Domain:</span> '
                              f'<span style="font-family:monospace">{self.session.domain}</span>')
        if host:
            if host.hostname not in ("Unknown", ""):
                info_parts.append(f'<span style="color:var(--text-muted)">Hostname:</span> '
                                  f'<span style="font-family:monospace">{host.hostname}</span>')
            if host.os_info not in ("Unknown", ""):
                info_parts.append(f'<span style="color:var(--text-muted)">OS:</span> '
                                  f'<span style="color:var(--text-secondary)">{host.os_info}</span>')
            smb_col = "#7aab7a" if host.smb_signing else "#f85149"
            smb_txt = "✓ SMB Signing On" if host.smb_signing else "⚡ SMB Signing OFF (relay candidate)"
            info_parts.append(f'<span style="color:{smb_col}">{smb_txt}</span>')
        info_card = ""
        if info_parts:
            info_card = (
                '<div class="card" style="margin-top:0">'
                '<div class="card-header"><div class="card-title">Target Info</div></div>'
                '<div style="display:flex;flex-wrap:wrap;gap:14px;font-size:12px;padding:2px 4px">'
                + "".join(f'<span>{p}</span>' for p in info_parts)
                + '</div></div>'
            )

        http_links_card = self._http_links_card()
        detail_card = self._detail_html_card()
        file_tree_html = self._file_tree_html()
        overview_content = stats_html + info_card + port_chips + http_links_card + detail_card

        sections_html = (
            self._section_html("overview", "Overview",
                               f"{self.ip} · {m}m{s:02d}s · {cmd_count} commands", overview_content)
            + self._section_html("exec-graph", "Execution Graph",
                                 "phase tree — what ran, what found, what skipped", exec_graph_html)
            + self._section_html("critical", "Critical Findings", "actionable attack surface", critical_html)
            + self._section_html("tcp", "TCP / UDP Ports", f"{tcp_count} TCP open{udp_note}",
                                 tcp_section_content)
            + (self._section_html("vuln", "Vulnerability Scan", "nmap --script vuln", vuln_html) if vuln_html else "")
            + (self._section_html("udp", "UDP Raw", "top-20 UDP output", udp_html) if udp_html else "")
            + (self._section_html("snmp", "SNMP", "snmp-check / onesixtyone", snmp_html) if snmp_html else "")
            + (self._section_html("smb", "SMB / enum4linux-ng", "parsed findings", e4l_html) if e4l_html else "")
            + (self._section_html("http", "HTTP Findings", "feroxbuster / whatweb / searchsploit", http_html) if http_html else "")
            + (self._section_html("files", "Output Files", "created files &amp; directories", file_tree_html) if file_tree_html else "")
            + self._section_html("commands", "Command Log", f"{cmd_count} commands recorded", cmd_blocks)
            + self._section_html("checklist", "OSCP チェックリスト",
                                 "チェックボックスで進捗管理 · 項目を開くと具体コマンド",
                                 '<div style="padding:4px 4px 14px">' + checklist_html() + '</div>')
        )

        nav_btns = "".join(
            f'<button class="nav-item" onclick="show(\'{sid}\',this)">{label}</button>'
            for sid, label in [
                ("overview",   "🏠 Overview"),
                ("exec-graph", "⚡ Exec Graph"),
                ("critical",   "⚠ Critical"),
                ("tcp",        "🔌 TCP/UDP"),
                ("vuln",       "💥 Vuln Scan"),
                ("udp",        "📡 UDP"),
                ("snmp",       "📡 SNMP"),
                ("smb",        "📁 SMB"),
                ("http",       "🌐 HTTP"),
                ("files",      "📂 Files"),
                ("commands",   "📋 Commands"),
                ("checklist",  "✅ Checklist"),
            ]
        )

        # SMB signing banner
        relay_banner = ""
        if host and not host.smb_signing:
            relay_banner = (
                '<div class="relay-banner">'
                f'⚡ {self.ip} — SMB signing disabled — relay candidate'
                '</div>'
            )

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxenum focus — {self.ip}</title>
{css}
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo" style="color:var(--accent-gold)">◈ focus</div>
      <div class="sidebar-subtitle" style="font-family:monospace;font-size:12px;color:var(--accent-silver)">{self.ip}</div>
      <div class="sidebar-subtitle" style="margin-top:2px">{name}</div>
    </div>
    <div class="sidebar-nav">
      <div class="nav-section">Navigation</div>
      {nav_btns}
    </div>
  </nav>
  <div class="main">
    <div class="topbar">
      <div class="topbar-title" style="color:var(--accent-gold)">◈ {name}
        <span style="font-size:12px;font-weight:400;color:var(--text-muted);margin-left:10px;font-family:monospace">{self.ip}</span>
      </div>
      <div style="display:flex;align-items:center;gap:12px">
        <a href="{detail_card_path}" target="_blank" class="copy-btn"
           style="text-decoration:none;font-size:11px">↗ detail.html</a>
        <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">☀ Light</button>
        <span class="topbar-meta">{now.strftime("%Y-%m-%d %H:%M")} &nbsp;·&nbsp; {m}m{s:02d}s &nbsp;·&nbsp; proxenum v1.6.3</span>
      </div>
    </div>
    <div class="content">
      {relay_banner}
      {sections_html}
    </div>
  </div>
</div>
{js}
<script>
document.addEventListener('DOMContentLoaded', () => {{
  const first = document.querySelector('.nav-item');
  if (first) first.click();
}});
</script>
</body>
</html>"""

    def _section_html(self, sid: str, title: str, desc: str, content: str) -> str:
        return (
            f'<div class="section" id="section-{sid}">'
            f'<div class="section-header">'
            f'<div class="section-title">{title}</div>'
            f'<div class="section-desc">{desc}</div>'
            f'</div>'
            f'<div class="card">{content}</div>'
            f'</div>'
        )

    def _tcp_rows(self, host) -> str:
        if not host or not host.open_ports:
            return _no_data(2)
        rows = []
        for port, svc in sorted(host.open_ports.items()):
            cls = "port-tag high-value" if port in HIGH_VALUE_PORTS else "port-tag"
            extra = self._unknown_search_link(port, svc, "tcp")
            rows.append(
                f'<tr><td><span class="{cls}">{port}/tcp</span></td>'
                f'<td style="color:var(--text-secondary)">{svc}{extra}</td></tr>'
            )
        if host.udp_ports:
            for port, svc in sorted(host.udp_ports.items()):
                cls = "port-tag high-value" if port in HIGH_VALUE_PORTS else "port-tag"
                extra = self._unknown_search_link(port, svc, "udp")
                rows.append(
                    f'<tr><td><span class="{cls}" style="opacity:.8">{port}/udp</span></td>'
                    f'<td style="color:var(--text-secondary)">{svc}{extra}</td></tr>'
                )
        return "\n".join(rows)

    @staticmethod
    def _unknown_search_link(port: int, svc: str, proto: str = "tcp") -> str:
        """Return a Google search link for unknown/uncommon services."""
        if svc.lower() not in ("unknown", "") and svc.strip():
            return ""
        q = f"{port}/{proto}+open+unknown+vuln"
        return (
            f' <a href="https://www.google.com/search?q={q}" target="_blank" '
            f'title="Search: {port}/{proto} open unknown" '
            f'style="color:var(--text-muted);font-size:10px;text-decoration:none;'
            f'vertical-align:middle">🔍</a>'
        )

    def _http_links_card(self) -> str:
        """Quick HTTP link card for all HTTP ports of this host (including high ports)."""
        host = self.session.hosts.get(self.ip)
        if not host:
            return ""
        links = []
        for port, svc in sorted(host.open_ports.items()):
            svc_l = svc.lower()
            if port not in HTTP_PORTS and "http" not in svc_l:
                continue
            is_https = port in {443, 8443} or "ssl" in svc_l or svc_l == "https"
            scheme = "https" if is_https else "http"
            url = f"{scheme}://{self.ip}" + (f":{port}" if port not in {80, 443} else "")
            links.append(
                f'<a href="{url}" target="_blank" class="http-link" '
                f'style="display:block;padding:5px 0;color:var(--accent-gold);text-decoration:none;'
                f'font-family:monospace;font-size:12px">{url}</a>'
            )
        if not links:
            return ""
        return (
            '<div class="card" style="margin-top:12px">'
            '<div class="card-header"><div class="card-title">Quick HTTP Links</div></div>'
            '<div style="padding:8px 14px">'
            + "\n".join(links)
            + '</div></div>'
        )

    def _detail_html_card(self) -> str:
        """Link to the nmap detail.html report for this host."""
        # detail.html is written by NmapScanner to {disp}/detail.html (relative
        # to cwd); _detail_href resolves it correctly for focus vs drill layout.
        detail_path = self._detail_href()
        return (
            '<div class="card" style="margin-top:12px">'
            '<div class="card-header"><div class="card-title">Nmap Detail Report</div></div>'
            '<div style="padding:8px 14px">'
            f'<a href="{detail_path}" target="_blank" class="http-link" '
            f'style="color:var(--accent-sage);font-size:12px">'
            f'↗ {detail_path}</a>'
            '</div></div>'
        )

    def _file_tree_html(self) -> str:
        """Show files created in the host output directory."""
        host = self.session.hosts.get(self.ip)
        disp = (host.display_name if host and host.display_name != self.ip
                else self.ip.replace(".", "_"))
        out_dir = Path(disp)
        if not out_dir.exists():
            return ""
        lines = [f'<span style="color:var(--accent-gold);font-weight:600">{out_dir.name}/</span>']
        seen_dirs: set = set()
        for f in sorted(out_dir.rglob("*")):
            rel = f.relative_to(out_dir)
            depth = len(rel.parts)
            # Show directory header once
            if f.is_dir():
                if str(rel) not in seen_dirs:
                    indent = "&nbsp;&nbsp;" * (depth - 1)
                    lines.append(
                        f'<span style="color:var(--text-muted)">{indent}└─ {f.name}/</span>'
                    )
                    seen_dirs.add(str(rel))
            else:
                indent = "&nbsp;&nbsp;" * (depth - 1)
                col = ("#c9a96e" if f.suffix == ".html" else
                       "#7aab7a" if f.suffix in (".txt", ".xml") else
                       "var(--text-secondary)")
                size = f.stat().st_size
                size_str = f" <span style='color:var(--text-muted);font-size:10px'>({size:,}B)</span>"
                lines.append(
                    f'<span style="color:{col}">{indent}├─ {f.name}</span>{size_str}'
                )
        return (
            '<div class="card">'
            '<div class="card-header"><div class="card-title">Output Files</div></div>'
            '<div style="padding:10px 14px;font-family:var(--font-mono);font-size:11px;line-height:1.9">'
            + "<br>".join(lines)
            + '</div></div>'
        )

    def _enum4linux_html(self) -> str:
        rec = next((r for r in self.session.command_history if "enum4linux-ng" in r.command), None)
        if not rec or not rec.output.strip():
            return ""
        parsed = parse_enum4linux(rec.output)
        parts = []
        if parsed.users:
            rows = "".join(f"<tr><td>{u}</td></tr>" for u in parsed.users)
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Users ({len(parsed.users)})</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Username</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if parsed.shares:
            rows = "".join(
                f"<tr><td style='font-family:var(--font-mono)'>{n}</td><td>{r}</td></tr>"
                for n, r in parsed.shares
            )
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Shares ({len(parsed.shares)})</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Share</th><th>Remark</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if parsed.password_policy:
            rows = "".join(
                f"<tr><td>{k}</td><td style='font-family:var(--font-mono)'>{v}</td></tr>"
                for k, v in parsed.password_policy.items()
            )
            parts.append(
                f'<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Password Policy</p>'
                f'<div class="table-wrapper" style="margin-bottom:12px"><table>'
                f'<thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table></div>'
            )
        if not parts:
            return ""
        safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            "".join(parts)
            + '<details style="margin-top:8px">'
            + '<summary style="cursor:pointer;color:var(--text-muted);font-size:12px">Raw output</summary>'
            + f'<div class="code-block output-block" style="margin-top:6px"><code>{safe}</code></div>'
            + '</details>'
        )

    def _vuln_html(self) -> str:
        rec = next((r for r in self.session.command_history if "vuln" in r.label.lower()), None)
        if not rec:
            return ""
        findings = parse_nmap_vuln(rec.output)
        if not findings:
            return '<p class="empty-msg">No vulnerabilities detected.</p>'
        rows = "".join(
            f'<tr><td><span class="port-tag high-value">{f.port}/tcp</span></td>'
            f'<td style="font-family:var(--font-mono);color:var(--danger)">{f.script}</td>'
            f'<td style="font-size:12px">{f.detail[:300]}</td></tr>'
            for f in findings
        )
        return (
            f'<div class="table-wrapper"><table>'
            f'<thead><tr><th>Port</th><th>Script</th><th>Detail</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _udp_html(self) -> str:
        rec = next((r for r in self.session.command_history if "UDP" in r.label), None)
        if not rec:
            return ""
        safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>'

    def _http_html(self) -> str:
        recs = [r for r in self.session.command_history
                if any(kw in r.label for kw in ("feroxbuster", "whatweb", "ffuf", "curl", "davtest"))]
        searchsploit_recs = [r for r in self.session.command_history if "searchsploit" in r.label.lower()]
        if not recs and not searchsploit_recs:
            return ""
        parts = []
        ferox_uid = [0]
        for rec in recs:
            label_html = (
                f'<p style="color:var(--accent-gold);font-weight:600;margin:12px 0 6px">'
                f'{rec.label}</p>'
            )
            if "whatweb" in rec.label and rec.output.strip():
                techs = parse_whatweb(rec.output)
                if techs:
                    cards = "".join(
                        f'<span class="port-tag" style="margin:2px;font-size:11px">'
                        f'<b>{name}</b>'
                        + (f'<span style="color:var(--text-muted)"> {detail[:60]}</span>' if detail else "")
                        + '</span>'
                        for name, detail in techs
                    )
                    parts.append(label_html + f'<div class="port-list" style="margin-bottom:8px">{cards}</div>')
                    continue
            if "curl" in rec.label and rec.output.strip():
                hdrs = parse_curl_headers(rec.output)
                if hdrs:
                    rows = "".join(
                        f"<tr><td style='font-family:var(--font-mono);color:var(--accent-gold);font-size:11px'>{k}</td>"
                        f"<td style='font-family:var(--font-mono);font-size:11px'>{v}</td></tr>"
                        for k, v in hdrs
                    )
                    parts.append(
                        label_html
                        + '<div class="table-wrapper" style="margin-bottom:8px"><table>'
                        '<thead><tr><th>Header</th><th>Value</th></tr></thead>'
                        f'<tbody>{rows}</tbody></table></div>'
                    )
                    continue
            if "feroxbuster" in rec.label and rec.output.strip():
                ferox_uid[0] += 1
                tree_html = self._ferox_tree_html(rec.output, uid=str(ferox_uid[0]))
                if tree_html:
                    parts.append(label_html + tree_html)
                    continue
                # No parseable URL entries — show meaningful error instead of raw dump
                if any(kw in rec.output for kw in ("Could not connect", "ERROR", "error")):
                    parts.append(
                        label_html
                        + '<div style="padding:8px 12px;color:var(--text-muted);font-size:12px;'
                        'background:#21262d;border-radius:6px;font-style:italic">'
                        '⚠ feroxbuster: target unreachable or no paths found</div>'
                    )
                    continue
            if "davtest" in rec.label:
                parts.append(label_html + self._davtest_html(rec.output))
                continue
            # fallback: raw code block (ffuf etc)
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(label_html + f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>')

        # Always append searchsploit section at the end
        parts.append(
            '<p style="color:var(--accent-gold);font-weight:600;margin:12px 0 6px">Searchsploit</p>'
            + self._searchsploit_section_html()
        )

        return "\n".join(parts)

    _INTERESTING_DIRS = {
        "admin", "administrator", "api", "login", "panel", "dashboard", "backup",
        "config", "upload", "uploads", "shell", "cmd", "exec", "phpmyadmin",
        "wp-admin", "wp-content", "manager", "console", "debug", "test", "secret",
        "private", "hidden", "cgi-bin", "setup", "install", "cms", "data",
        "password", "passwd", "credentials", "keys", "token", "auth",
    }

    @staticmethod
    def _file_icon(name: str, is_dir: bool) -> str:
        if is_dir:
            return "📁"
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return {
            "php": "⚡", "asp": "⚡", "aspx": "⚡", "jsp": "⚡", "cgi": "⚡",
            "py": "⚡", "rb": "⚡", "pl": "⚡", "sh": "⚡",
            "html": "🌐", "htm": "🌐",
            "txt": "📝", "md": "📝", "conf": "📝", "config": "📝", "cfg": "📝",
            "ini": "📝", "env": "📝", "xml": "📝", "json": "📝", "yaml": "📝",
            "js": "📜", "css": "🎨",
            "zip": "📦", "tar": "📦", "gz": "📦", "7z": "📦", "bak": "💾",
            "jpg": "🖼", "jpeg": "🖼", "png": "🖼", "gif": "🖼", "svg": "🖼",
            "pdf": "📑", "sql": "🗄", "db": "🗄",
        }.get(ext, "📄")

    @staticmethod
    def _status_badge(code: int) -> str:
        if not code:
            return ""
        col = {"2": "#7aab7a", "3": "#c9a96e", "4": "#8b949e", "5": "#f85149"}.get(str(code)[0], "#8b949e")
        bg = col + "22"
        border = col + "55"
        return (
            f'<span style="font-size:10px;padding:1px 5px;border-radius:10px;'
            f'background:{bg};border:1px solid {border};color:{col};flex-shrink:0">{code}</span>'
        )

    # ANSI escape code pattern — strip before parsing feroxbuster output
    _ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\r")

    def _ferox_tree_html(self, output: str, uid: str = "0") -> str:
        """Build an interactive JS-powered file explorer from feroxbuster output."""
        import re as _re
        from urllib.parse import urlparse

        # Strip ANSI escape codes and carriage returns that corrupt the parse
        clean = self._ANSI_RE.sub("", output)

        entries: list[tuple[int, str]] = []
        base_url = ""
        for line in clean.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format 1 (full): STATUS  METHOD  Nl  Nw  Nc  https://...
            m = _re.match(
                r"(\d{3})\s+(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+\S+\s+\S+\s+\S+\s+(https?://[^\s=>]+)",
                line,
            )
            if not m:
                # Format 2 (compact/--silent newer): STATUS  https://...
                m = _re.match(r"(\d{3})\s+(https?://[^\s=>]+)", line)
            if not m:
                # Format 3: bare URL line (very old --silent or custom output)
                if line.startswith(("http://", "https://")):
                    url = line.split()[0]
                    parsed = urlparse(url)
                    if not base_url and parsed.scheme:
                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                    entries.append((200, parsed.path.rstrip("/") or "/"))
                continue
            code, url = int(m.group(1)), m.group(2).split()[0]
            parsed = urlparse(url)
            if not base_url and parsed.scheme:
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            entries.append((code, parsed.path.rstrip("/") or "/"))

        if not entries:
            return ""

        paths: dict[str, int] = {}
        for code, p in entries:
            if p not in paths or code < 400:
                paths[p] = code

        # Build trie
        tree: dict = {}
        for p in sorted(paths):
            node = tree
            for part in [x for x in p.split("/") if x]:
                node = node.setdefault(part, {})

        _node_id = [0]

        def _node(node: dict, path_so_far: str = "") -> str:
            html = ""
            for name, children in sorted(node.items()):
                full_path = f"{path_so_far}/{name}"
                code = paths.get(full_path, paths.get(full_path + "/", 0))
                is_dir = bool(children)
                is_int = name.lower() in self._INTERESTING_DIRS
                icon = self._file_icon(name, is_dir)
                badge = self._status_badge(code)
                star = '<span style="color:#f0883e;font-size:10px;flex-shrink:0">★</span>' if is_int else ""
                name_col = "#f0883e" if is_int else "#c0c8d4"
                name_fw = "font-weight:600;" if is_int else ""
                link = (
                    f'<a href="{base_url}{full_path}" target="_blank" onclick="event.stopPropagation()" '
                    f'style="color:#656d76;font-size:11px;text-decoration:none;padding:0 3px;'
                    f'border-radius:3px;flex-shrink:0" title="{base_url}{full_path}">↗</a>'
                ) if base_url else ""
                _node_id[0] += 1

                row_style = (
                    "display:flex;align-items:center;gap:5px;padding:3px 8px;"
                    "white-space:nowrap;overflow:hidden"
                )
                name_style = (
                    f"font-family:var(--font-mono,monospace);font-size:12px;"
                    f"color:{name_col};{name_fw}flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis"
                )

                if is_dir:
                    child_html = _node(children, full_path)
                    html += (
                        f'<details data-path="{full_path}" open style="border:none">'
                        f'<summary style="{row_style};cursor:pointer;list-style:none;'
                        f'border-radius:4px;transition:background .1s"'
                        f' onmouseover="this.style.background=\'#21262d\'"'
                        f' onmouseout="this.style.background=\'\'">'
                        f'<span style="font-size:9px;color:#656d76;width:10px;flex-shrink:0">▼</span>'
                        f'<span style="font-size:13px;flex-shrink:0">{icon}</span>'
                        f'<span style="{name_style}">{name}/</span>'
                        f'{star}{badge}{link}'
                        f'</summary>'
                        f'<div style="padding-left:20px;border-left:1px solid #30363d;margin-left:14px">'
                        f'{child_html}</div>'
                        f'</details>'
                    )
                else:
                    html += (
                        f'<div data-path="{full_path}" style="{row_style};border-radius:4px;'
                        f'transition:background .1s"'
                        f' onmouseover="this.style.background=\'#21262d\'"'
                        f' onmouseout="this.style.background=\'\'">'
                        f'<span style="width:10px;flex-shrink:0"></span>'
                        f'<span style="font-size:13px;flex-shrink:0">{icon}</span>'
                        f'<span style="{name_style}">{name}</span>'
                        f'{star}{badge}{link}'
                        f'</div>'
                    )
            return html

        inner = _node(tree)
        if not inner:
            return ""

        toolbar_style = (
            "display:flex;align-items:center;gap:8px;padding:8px 12px;"
            "border-bottom:1px solid #30363d;background:#21262d;flex-wrap:wrap"
        )
        search_style = (
            "flex:1;min-width:140px;background:#0d1117;border:1px solid #30363d;"
            "border-radius:6px;padding:5px 10px;color:#c0c8d4;font-size:12px;outline:none"
        )
        btn_style = (
            "background:none;border:1px solid #30363d;color:#8b949e;font-size:11px;"
            "padding:4px 8px;border-radius:6px;cursor:pointer;white-space:nowrap"
        )

        js = f"""
<script>
(function(){{
var TREE_ID = 'dt-{uid}';
function getBody(){{ return document.getElementById(TREE_ID); }}
window['dirFilter_{uid}'] = function(inp){{
  var q = inp.value.trim().toLowerCase();
  var body = getBody(); if(!body) return;
  var all = Array.from(body.querySelectorAll('[data-path]'));
  if(!q){{
    all.forEach(function(el){{el.style.display='';}});
    body.querySelectorAll('details').forEach(function(d){{
      d.open = d.dataset.wasopen !== '0';
    }});
    return;
  }}
  body.querySelectorAll('details').forEach(function(d){{
    if(d.dataset.wasopen===undefined) d.dataset.wasopen = d.open ? '1' : '0';
    d.open = true;
  }});
  var visible = new Set();
  all.forEach(function(el){{
    if(el.dataset.path.toLowerCase().includes(q)) visible.add(el.dataset.path);
  }});
  var toAdd = [];
  visible.forEach(function(p){{
    var parts = p.split('/');
    for(var i=1;i<=parts.length;i++){{
      var ancestor = parts.slice(0,i).join('/') || '/';
      toAdd.push(ancestor);
    }}
  }});
  toAdd.forEach(function(p){{visible.add(p);}});
  all.forEach(function(el){{
    el.style.display = visible.has(el.dataset.path) ? '' : 'none';
  }});
}};
window['dirExpand_{uid}'] = function(){{
  getBody().querySelectorAll('details').forEach(function(d){{d.open=true;}});
}};
window['dirCollapse_{uid}'] = function(){{
  getBody().querySelectorAll('details').forEach(function(d){{d.open=false;}});
}};
}})();
</script>"""

        return (
            js
            + f'<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;'
            f'overflow:hidden;margin-bottom:12px">'
            f'<div style="{toolbar_style}">'
            f'<input type="text" placeholder="🔍 Filter paths..." style="{search_style}"'
            f' oninput="dirFilter_{uid}(this)">'
            f'<button style="{btn_style}" onclick="dirExpand_{uid}()">＋ 展開</button>'
            f'<button style="{btn_style}" onclick="dirCollapse_{uid}()">－ 格納</button>'
            f'<span style="color:#656d76;font-size:11px;white-space:nowrap">'
            f'{len(paths)} paths</span>'
            f'<span style="color:#8b949e;font-size:11px;flex:1;text-align:right;'
            f'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{base_url}</span>'
            f'</div>'
            f'<div id="dt-{uid}" style="padding:6px 4px;max-height:520px;overflow-y:auto">'
            f'{inner}</div></div>'
        )

    @staticmethod
    def _davtest_html(output: str) -> str:
        """Parse davtest output and show a formatted result card."""
        import re as _re
        if not output.strip():
            return ""

        results: list[tuple[str, str, str]] = []  # (method, ext_or_detail, succeed)
        for line in output.splitlines():
            line = line.strip()
            m = _re.match(r"(PUT|COPY|MOVE|DELETE|PROPFIND|MKCOL|LOCK)\s+([\w\.]+)\s+(SUCCEED|FAIL)(.*)", line, _re.I)
            if m:
                results.append((m.group(1), m.group(2), m.group(3).upper()))
                continue
            m2 = _re.match(r"(OPEN|DIRECTORY)\s+(SUCCEED|FAIL)(.*)", line, _re.I)
            if m2:
                results.append((m2.group(1), "", m2.group(2).upper()))

        if not results:
            safe = output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return f'<div class="code-block output-block"><code>{safe}</code></div>'

        # Executables that are dangerous if PUT succeeds
        _EXEC_EXTS = {"php", "asp", "aspx", "jsp", "cgi", "pl", "sh", "py", "rb"}

        rows = ""
        critical_found = False
        for method, detail, status in results:
            ok = (status == "SUCCEED")
            is_critical = ok and method == "PUT" and detail.lower().strip(".") in _EXEC_EXTS
            if is_critical:
                critical_found = True
            col = "#f85149" if is_critical else ("#7aab7a" if ok else "#656d76")
            badge_txt = "🔴 SUCCEED" if is_critical else ("✓ SUCCEED" if ok else "FAIL")
            badge_style = (
                f"font-size:10px;padding:2px 6px;border-radius:8px;"
                f"background:{col}22;border:1px solid {col}55;color:{col}"
            )
            label = f"{method} {detail}".strip()
            rows += (
                f"<tr>"
                f"<td style='font-family:var(--font-mono,monospace);font-size:12px'>{label}</td>"
                f"<td><span style='{badge_style}'>{badge_txt}</span></td>"
                f"</tr>"
            )

        warning = (
            '<div style="margin-bottom:8px;padding:6px 10px;background:#f8514922;'
            'border:1px solid #f8514955;border-radius:6px;color:#f85149;font-size:12px">'
            '🔴 <strong>WebDAV executable upload succeeded!</strong> RCE possible.</div>'
            if critical_found else ""
        )

        return (
            warning
            + '<div class="table-wrapper" style="margin-bottom:8px"><table>'
            + '<thead><tr><th>Test</th><th>Result</th></tr></thead>'
            + f'<tbody>{rows}</tbody></table></div>'
        )

    def _searchsploit_section_html(self) -> str:
        """Collect all searchsploit command records and render as a findings table."""
        recs = [r for r in self.session.command_history if "searchsploit" in r.label.lower()]
        if not recs:
            return (
                '<div style="padding:12px;color:var(--text-muted);font-size:12px;'
                'text-align:center">searchsploit — no results recorded</div>'
            )

        import re as _re
        _RCE_RE = _re.compile(
            r"(?i)(remote\s*code|rce|\brce\b|command\s*inject|file\s*inclus|deseria"
            r"|sql\s*inject|privilege\s*escal|local\s*file|path\s*trav)", _re.I
        )
        _SKIP_RE = _re.compile(r"(?i)(dos|denial.of.service|xss|csrf|cross.site)", _re.I)

        all_rows = ""
        total = 0
        for rec in recs:
            query = rec.label.replace("searchsploit", "").strip("[] ")
            section_rows = ""
            for line in rec.output.splitlines():
                if "|" not in line:
                    continue
                parts = line.split("|")
                if len(parts) < 2:
                    continue
                title = parts[0].strip()
                path = parts[1].strip() if len(parts) > 1 else ""
                if not title or "Title" in title or "---" in title or "Path" in path:
                    continue
                if _SKIP_RE.search(title):
                    continue
                is_rce = bool(_RCE_RE.search(title))
                row_col = "#f85149" if is_rce else "#c0c8d4"
                rce_badge = (
                    '<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                    'background:#f8514922;border:1px solid #f8514955;color:#f85149;'
                    'margin-right:4px">RCE</span>'
                    if is_rce else ""
                )
                path_short = path.split("/")[-1] if path else path
                section_rows += (
                    f"<tr>"
                    f"<td style='font-size:11px;color:{row_col}'>{rce_badge}{title}</td>"
                    f"<td style='font-family:var(--font-mono,monospace);font-size:10px;"
                    f"color:var(--text-muted)'>{path_short}</td>"
                    f"</tr>"
                )
                total += 1
            if section_rows:
                all_rows += (
                    f'<tr><td colspan="2" style="padding-top:8px;padding-bottom:2px;'
                    f'color:var(--accent-gold);font-weight:600;font-size:11px">'
                    f'[{query}]</td></tr>'
                    + section_rows
                )

        if not all_rows:
            return (
                '<div style="padding:12px;color:var(--text-muted);font-size:12px;text-align:center">'
                'searchsploit — no exploits found matching scanned versions</div>'
            )

        return (
            f'<div style="margin-bottom:4px;font-size:11px;color:var(--text-muted)">'
            f'{total} exploit(s) — DoS/XSS filtered</div>'
            + '<div class="table-wrapper"><table>'
            + '<thead><tr><th>Exploit Title</th><th>File</th></tr></thead>'
            + f'<tbody>{all_rows}</tbody></table></div>'
        )

    # ─── execution graph ──────────────────────────────────────────────────────

    def _exec_graph_html(self) -> str:
        """Phase-based logic tree: Phase 1 (TCP) → Phase 2 (Vuln/UDP/SNMP) → Phase 3 (Services)."""
        import re as _re

        history = self.session.command_history
        host = self.session.hosts.get(self.ip)
        open_ports: set[int] = set(host.open_ports.keys()) if host else set()

        if not history:
            return '<p class="empty-msg">No commands recorded.</p>'

        # ── Classify each record into a phase ─────────────────────────────────
        def _phase(label: str) -> int:
            ll = label.lower()
            # Phase 2: vuln scan, UDP, SNMP (even if label has "nmap")
            if any(k in ll for k in ("vuln", " udp ", "nmap udp", "snmp", "onesixtyone")):
                return 2
            # Phase 1: port discovery commands
            if any(k in ll for k in ("rustscan", "nmap")):
                return 1
            return 3

        def _service(label: str) -> str:
            ll = label.lower()
            if any(k in ll for k in ("smb", "enum4linux", "smbclient")):
                return "SMB"
            if "rdp" in ll:
                return "RDP"
            if any(k in ll for k in ("whatweb", "curl headers", "feroxbuster", "davtest",
                                     "webdav", "ffuf", "git-dumper", "lfi params")):
                return "HTTP"
            if "searchsploit" in ll and "(snmp)" not in ll:
                return "HTTP"  # HTTP searchsploit (with brackets in label)
            if "ldap" in ll or "ldapsearch" in ll:
                return "LDAP"
            if "ftp" in ll:
                return "FTP"
            if "ssh" in ll:
                return "SSH"
            if "mssql" in ll:
                return "MSSQL"
            if "mysql" in ll:
                return "MySQL"
            if "postgres" in ll:
                return "PostgreSQL"
            if "redis" in ll:
                return "Redis"
            if "smtp" in ll:
                return "SMTP"
            return "Other"

        def _status(rec) -> tuple[str, str]:
            out = rec.output or ""
            ll = rec.label.lower()
            if (("succeed" in out.lower() and "put" in out.lower())
                    or "rce" in out.lower()
                    or ("[+]" in out and "(pwn3d!)" in out.lower())
                    or ("/.git" in out.lower() and "git-dumper" in ll)
                    or "lfi" in ll):
                return "🔴", "#f85149"
            if rec.return_code == 0 and out.strip() and len(out.strip()) > 50:
                return "✅", "#7aab7a"
            if rec.return_code == 0:
                return "⚠️", "#c9a96e"
            return "❌", "#656d76"

        def _finding(rec) -> str:
            out = rec.output or ""
            ll = rec.label.lower()
            if "whatweb" in ll:
                m = _re.search(r"\[([^\[\]]+?)\s+(\d+\.\d[\d\.]*)\]", out)
                if m:
                    return f"{m.group(1)} {m.group(2)}"
                m2 = _re.search(r"\[([A-Za-z][^\[\]]{2,40})\]", out)
                if m2:
                    return m2.group(1)[:60]
            if "feroxbuster" in ll:
                count = len([ln for ln in out.splitlines()
                             if _re.match(r"\s*\d{3}\s+", ln)])
                if count:
                    return f"{count} path(s)"
            if "nmap" in ll or "rustscan" in ll:
                ports = _re.findall(r"(\d+)/(?:tcp|udp)\s+open", out)
                if ports:
                    ps = ", ".join(sorted(set(ports), key=int)[:6])
                    return f"{len(ports)} open: {ps}"
            if "searchsploit" in ll:
                hits = [ln for ln in out.splitlines()
                        if "|" in ln and "Title" not in ln and "---" not in ln]
                if hits:
                    return f"{len(hits)} exploit(s)"
                return "no hits"
            if any(k in ll for k in ("smb", "enum4linux", "smbclient", "nxc smb")):
                um = _re.search(r"(\d+)\s+user", out, _re.I)
                if um:
                    return f"{um.group(1)} user(s)"
                sm = _re.search(r"(\d+)\s+share", out, _re.I)
                if sm:
                    return f"{sm.group(1)} share(s)"
                if "[+]" in out:
                    return "authenticated"
            return ""

        # ── Build one command row ─────────────────────────────────────────────
        def _row(rec, is_last: bool = False, depth: int = 0) -> str:
            emoji, s_col = _status(rec)
            badge = _finding(rec)
            safe_lbl = rec.label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            dur = f"{rec.duration:.1f}s"

            conn = "└─" if is_last else "├─"
            pad_left = 4 + depth * 16

            badge_html = ""
            if badge:
                is_crit = emoji == "🔴"
                bg  = "#f8514922" if is_crit else "#21262d"
                bdr = "#f8514955" if is_crit else "#30363d"
                col = "#f85149" if is_crit else "#8b949e"
                be  = badge.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                badge_html = (
                    f'<span style="font-size:10px;padding:1px 6px;border-radius:8px;'
                    f'background:{bg};border:1px solid {bdr};color:{col};'
                    f'white-space:nowrap;flex-shrink:0;margin-left:auto">{be}</span>'
                )

            return (
                f'<div style="display:flex;align-items:center;gap:6px;'
                f'padding:2px 6px 2px {pad_left}px;border-radius:3px;'
                f'background:{s_col}08;margin-bottom:1px;min-height:22px">'
                f'<span style="color:#444c56;font-family:monospace;font-size:11px;'
                f'flex-shrink:0;width:16px;text-align:right">{conn}</span>'
                f'<span style="font-size:11px;flex-shrink:0">{emoji}</span>'
                f'<span style="font-family:monospace;font-size:11px;color:#c0c8d4;'
                f'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
                f'{safe_lbl}</span>'
                f'{badge_html}'
                f'<span style="font-size:10px;color:#444c56;flex-shrink:0;white-space:nowrap">'
                f'{dur}</span>'
                f'</div>'
            )

        # ── Phase block wrapper ───────────────────────────────────────────────
        def _phase_block(num: int, title: str, col: str, icon: str, body: str) -> str:
            return (
                f'<div style="display:flex;gap:0;margin-bottom:10px">'
                f'<div style="width:4px;background:{col};border-radius:4px 0 0 4px;'
                f'flex-shrink:0"></div>'
                f'<div style="flex:1;background:{col}0a;border:1px solid {col}2a;'
                f'border-left:none;border-radius:0 8px 8px 0;padding:8px 12px;min-width:0">'
                f'<div style="font-size:10px;font-weight:700;letter-spacing:.08em;'
                f'color:{col};text-transform:uppercase;margin-bottom:6px">'
                f'{icon} Phase {num} — {title}</div>'
                f'{body}'
                f'</div></div>'
            )

        # ── Service sub-group ─────────────────────────────────────────────────
        _SVC_COL = {
            "SMB": "#e3b341", "HTTP": "#58a6ff", "LDAP": "#8b7aa8",
            "FTP": "#c9a96e", "SSH": "#56d364", "MSSQL": "#f85149",
            "MySQL": "#f85149", "PostgreSQL": "#7aab7a", "Redis": "#c9a96e",
            "SMTP": "#8b949e", "RDP": "#f85149", "Other": "#8b949e",
        }
        _SVC_ICO = {
            "SMB": "📁", "HTTP": "🌐", "LDAP": "🔐", "FTP": "📂",
            "SSH": "🔑", "MSSQL": "🗄", "MySQL": "🗄", "PostgreSQL": "🗄",
            "Redis": "🗄", "SMTP": "✉", "RDP": "🖥", "Other": "⚙",
        }

        def _svc_group(svc: str, recs: list) -> str:
            col  = _SVC_COL.get(svc, "#8b949e")
            icon = _SVC_ICO.get(svc, "⚙")
            rows = "".join(_row(r, i == len(recs) - 1) for i, r in enumerate(recs))
            return (
                f'<div style="margin-bottom:6px">'
                f'<div style="display:flex;align-items:center;gap:6px;'
                f'padding:3px 6px;border-left:2px solid {col};margin-bottom:2px">'
                f'<span style="font-size:12px">{icon}</span>'
                f'<span style="font-size:11px;font-weight:600;color:{col}">{svc}</span>'
                f'</div>'
                f'<div style="padding-left:14px;border-left:1px dashed {col}44;margin-left:6px">'
                f'{rows}</div></div>'
            )

        # ── Separate records into phases ──────────────────────────────────────
        ph1 = [r for r in history if _phase(r.label) == 1]
        ph2 = [r for r in history if _phase(r.label) == 2]
        ph3 = [r for r in history if _phase(r.label) == 3]

        # Group phase-3 by service
        p3_groups: dict[str, list] = {}
        for r in ph3:
            svc = _service(r.label)
            p3_groups.setdefault(svc, []).append(r)

        # ── Build phase 1 ─────────────────────────────────────────────────────
        parts = []
        if ph1:
            port_note = ""
            if host and host.open_ports:
                ps = sorted(host.open_ports)
                port_note = f" · {len(ps)} port(s): {', '.join(str(p) for p in ps[:8])}{'…' if len(ps) > 8 else ''}"
            rows = "".join(_row(r, i == len(ph1) - 1) for i, r in enumerate(ph1))
            parts.append(_phase_block(1, f"TCP Discovery{port_note}", "#58a6ff", "🔍", rows))

        # ── Build phase 2 ─────────────────────────────────────────────────────
        if ph2:
            rows = "".join(_row(r, i == len(ph2) - 1) for i, r in enumerate(ph2))
            parts.append(_phase_block(2, "Vuln / UDP / SNMP", "#f85149", "💥", rows))

        # ── Build phase 3 ─────────────────────────────────────────────────────
        if p3_groups:
            _SVC_ORDER = ["SMB", "HTTP", "LDAP", "FTP", "SSH", "MSSQL",
                          "MySQL", "PostgreSQL", "Redis", "SMTP", "RDP", "Other"]
            body = "".join(
                _svc_group(svc, p3_groups[svc])
                for svc in _SVC_ORDER if svc in p3_groups
            )
            parts.append(_phase_block(3, "Service Enumeration", "#c9a96e", "⚡", body))

        # ── NOT RUN block ─────────────────────────────────────────────────────
        not_run: list[tuple[str, str]] = []
        udp_ports = set(host.udp_ports.keys()) if host else set()
        http_ports = {80, 443, 8080, 8443}
        if not (open_ports & http_ports):
            not_run.append(("🌐 HTTP", "no HTTP port detected"))
        elif not any("feroxbuster" in r.label.lower() for r in history):
            not_run.append(("🌐 HTTP", "port open — not yet enumerated"))
        if 445 not in open_ports:
            not_run.append(("📁 SMB", "no port 445"))
        elif not any("smb" in r.label.lower() or "enum4linux" in r.label.lower()
                     for r in history):
            not_run.append(("📁 SMB", "port open — not yet enumerated"))
        if not any(p in open_ports for p in (389, 636)):
            not_run.append(("🔐 LDAP", "no LDAP port"))
        if 161 not in udp_ports:
            not_run.append(("📡 SNMP", "UDP/161 not open"))
        if not any("vuln" in r.label.lower() for r in history):
            not_run.append(("💥 Vuln Scan", "not run"))

        if not_run:
            nr_rows = "".join(
                f'<div style="display:flex;gap:6px;align-items:center;padding:2px 4px;'
                f'border-radius:3px;margin-bottom:1px;opacity:.5">'
                f'<span style="color:#444c56;font-family:monospace;font-size:11px;width:16px">└─</span>'
                f'<span style="font-size:11px">⊘</span>'
                f'<span style="font-family:monospace;font-size:11px;color:#656d76">{lbl}</span>'
                f'<span style="font-size:10px;color:#444c56;font-style:italic;margin-left:auto">{rsn}</span>'
                f'</div>'
                for lbl, rsn in not_run
            )
            parts.append(
                f'<div style="display:flex;gap:0;margin-bottom:10px;opacity:.65">'
                f'<div style="width:4px;background:#444c56;border-radius:4px 0 0 4px;flex-shrink:0"></div>'
                f'<div style="flex:1;background:#21262d;border:1px solid #30363d;'
                f'border-left:none;border-radius:0 8px 8px 0;padding:8px 12px;min-width:0">'
                f'<div style="font-size:10px;font-weight:700;color:#656d76;'
                f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">'
                f'⊘ Not Run / Skipped</div>'
                f'{nr_rows}</div></div>'
            )

        if not parts:
            return '<p class="empty-msg">No commands recorded.</p>'

        return (
            '<div style="display:flex;flex-direction:column;gap:0;font-size:12px">'
            + "".join(parts)
            + '</div>'
        )

    # ─── SNMP section ──────────────────────────────────────────────────────────

    def _snmp_html(self) -> str:
        """Parse snmp-check / onesixtyone output from command_history."""
        import re as _re2
        recs = [r for r in self.session.command_history
                if any(kw in r.label.lower() for kw in ("snmp", "onesixtyone"))]
        if not recs:
            return ""

        parts = []
        for rec in recs:
            if not rec.output.strip():
                continue
            safe_label = rec.label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            label_html = (
                f'<p style="color:var(--accent-gold);font-weight:600;margin:12px 0 6px">'
                f'{safe_label}</p>'
            )

            # Try to parse snmp-check sections
            sections: list[tuple[str, str]] = []
            current_section = None
            current_lines: list[str] = []
            for line in rec.output.splitlines():
                m = _re2.match(r"\[\*\]\s+(.+)", line)
                if m:
                    if current_section is not None:
                        sections.append((current_section, "\n".join(current_lines)))
                    current_section = m.group(1).strip()
                    current_lines = []
                elif current_section is not None:
                    current_lines.append(line)
            if current_section is not None:
                sections.append((current_section, "\n".join(current_lines)))

            if sections:
                sections_html = ""
                for sec_title, sec_content in sections:
                    is_software = "software" in sec_title.lower() or "component" in sec_title.lower()
                    content_lines = [l for l in sec_content.splitlines() if l.strip()]
                    if not content_lines:
                        continue
                    safe_content = (sec_content
                                    .replace("&", "&amp;")
                                    .replace("<", "&lt;")
                                    .replace(">", "&gt;"))
                    highlight_style = (
                        "border-left:3px solid #c9a96e;padding-left:8px;"
                        if is_software else ""
                    )
                    title_col = "#c9a96e" if is_software else "var(--accent-gold)"
                    sections_html += (
                        f'<details open style="margin-bottom:6px">'
                        f'<summary style="cursor:pointer;font-weight:600;color:{title_col};'
                        f'font-size:12px;padding:4px 0;{highlight_style}">'
                        f'{"⭐ " if is_software else ""}{sec_title}</summary>'
                        f'<div class="code-block output-block" style="margin:4px 0 8px;'
                        f'font-size:11px"><code>{safe_content}</code></div>'
                        f'</details>'
                    )
                if sections_html:
                    parts.append(label_html + sections_html)
                    continue

            # Fallback: raw output
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(
                label_html
                + f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>'
            )

        # Also show searchsploit records that follow SNMP (if any)
        searchsploit_after = [r for r in self.session.command_history
                              if "searchsploit" in r.label.lower() and r.output.strip()]
        if searchsploit_after and parts:
            parts.append(
                '<p style="color:var(--accent-gold);font-weight:600;margin:12px 0 6px">'
                'Searchsploit (SNMP-related)</p>'
                + self._searchsploit_section_html()
            )

        return "\n".join(parts) if parts else ""

    # ─── git-dumper section ────────────────────────────────────────────────────

    def _git_dumper_html(self) -> str:
        """Show a critical card if git-dumper ran and found something."""
        rec = next((r for r in self.session.command_history
                    if "git-dumper" in r.label.lower() or "git-dumper" in r.command.lower()), None)
        if not rec or not rec.output.strip():
            return ""

        # Try to extract dump location from command
        import re as _re2
        dump_loc = ""
        m = _re2.search(r"git-dumper\s+\S+\s+(\S+)", rec.command)
        if m:
            dump_loc = m.group(1)

        safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        return (
            '<div style="margin-bottom:12px;padding:10px 14px;background:#f8514922;'
            'border:1px solid #f8514955;border-radius:8px">'
            '<div style="color:#f85149;font-weight:700;font-size:14px;margin-bottom:6px">'
            '🔴 .git directory exposed and dumped</div>'
            '<div style="font-size:12px;color:#c0c8d4;margin-bottom:8px">'
            + (f'<span style="color:var(--text-muted)">Dump location:</span> '
               f'<code style="background:#161b22;padding:2px 6px;border-radius:4px">{dump_loc}</code>'
               if dump_loc else "")
            + '</div>'
            '<div style="font-size:12px;color:#c9a96e;margin-bottom:8px">'
            'Recommend: '
            '<code style="background:#161b22;padding:2px 6px;border-radius:4px">git log</code> &nbsp;'
            '<code style="background:#161b22;padding:2px 6px;border-radius:4px">git diff</code> &nbsp;'
            '<code style="background:#161b22;padding:2px 6px;border-radius:4px">grep -r "password\\|secret\\|key"</code>'
            '</div>'
            '<details>'
            '<summary style="cursor:pointer;color:var(--text-muted);font-size:12px">Raw output</summary>'
            f'<div class="code-block output-block" style="margin-top:6px"><code>{safe}</code></div>'
            '</details>'
            '</div>'
        )

    # ─── LFI params section ───────────────────────────────────────────────────

    def _lfi_params_html(self) -> str:
        """Show suspicious LFI parameter URLs from command_history."""
        import re as _re2
        rec = next((r for r in self.session.command_history
                    if "lfi params" in r.label.lower() or "lfi" in r.label.lower()), None)
        if not rec or not rec.output.strip():
            return ""

        # Extract URLs from output
        urls = _re2.findall(r"https?://[^\s\'\"\]\)]+", rec.output)
        if not urls:
            # Treat each non-empty line as a URL/param
            urls = [l.strip() for l in rec.output.splitlines() if l.strip()]

        payloads = [
            "?page=../../../etc/passwd",
            "?file=../../../etc/shadow",
            "?include=../../../etc/passwd",
            "?path=../../../proc/self/environ",
        ]

        url_links = "".join(
            f'<div style="margin:2px 0">'
            f'<a href="{u}" target="_blank" style="font-family:monospace;font-size:11px;'
            f'color:#c9a96e;word-break:break-all">{u}</a>'
            f'</div>'
            for u in urls[:30]
        )
        payload_chips = "".join(
            f'<code style="display:inline-block;margin:2px;background:#161b22;'
            f'border:1px solid #30363d;padding:2px 7px;border-radius:4px;'
            f'font-size:11px;color:#c9a96e">{p}</code>'
            for p in payloads
        )

        return (
            '<div style="margin-bottom:12px;padding:10px 14px;background:#c9a96e22;'
            'border:1px solid #c9a96e55;border-radius:8px">'
            '<div style="color:#c9a96e;font-weight:700;font-size:14px;margin-bottom:6px">'
            '⚠ Potential LFI Parameters Detected</div>'
            '<div style="margin-bottom:8px">'
            + url_links
            + '</div>'
            '<div style="color:var(--text-muted);font-size:11px;margin-bottom:4px">'
            'Suggested test payloads:</div>'
            '<div>' + payload_chips + '</div>'
            '</div>'
        )

    # ─── critical findings ────────────────────────────────────────────────────

    def _focus_critical_html(self) -> str:
        parts: list[str] = []
        history = self.session.command_history

        # git-dumper: flag as Critical
        git_html = self._git_dumper_html()
        if git_html:
            parts.append(
                '<p style="color:#f85149;font-weight:600;margin-bottom:6px">'
                '🔴 Git Repository Exposed</p>'
                + git_html
            )

        # LFI params: flag as Critical
        lfi_html = self._lfi_params_html()
        if lfi_html:
            parts.append(
                '<p style="color:#c9a96e;font-weight:600;margin-bottom:6px">'
                '⚠ LFI Parameter Candidates</p>'
                + lfi_html
            )

        # WebDAV PUT enabled: flag as Critical
        for rec in history:
            if "davtest" not in rec.label.lower() or not rec.output.strip():
                continue
            import re as _re3
            import re as _re_dav
            _EXEC_EXTS_SET = {"php", "asp", "aspx", "jsp", "cgi", "pl", "sh", "py", "rb"}
            for line in rec.output.splitlines():
                m = _re_dav.match(
                    r"(PUT)\s+([\w\.]+)\s+(SUCCEED)(.*)", line.strip(), _re_dav.I
                )
                if m and m.group(2).lower().strip(".") in _EXEC_EXTS_SET:
                    ext = m.group(2)
                    parts.append(
                        '<div style="margin-bottom:12px;padding:8px 12px;background:#f8514922;'
                        'border:1px solid #f8514955;border-radius:8px">'
                        '<span style="color:#f85149;font-weight:700">🔴 WebDAV PUT Enabled</span>'
                        f'<span style="color:#c0c8d4;font-size:12px;margin-left:8px">'
                        f'PUT .{ext} SUCCEED — executable upload possible, RCE likely</span>'
                        '</div>'
                    )
                    break

        # Local-auth credentials: show clearly
        local_creds = [c for c in self.session.credentials
                       if c.success and getattr(c, 'local_auth', False)]
        if local_creds:
            _admin_badge = '<span class="badge badge-gold">👑 Admin</span>'
            _non_admin_badge = '<span class="badge badge-muted">—</span>'
            local_rows = "".join(
                f"<tr>"
                f"<td style='font-family:var(--font-mono)'>{c.username}</td>"
                f"<td style='font-family:var(--font-mono);color:var(--accent-gold)'>{c.password}</td>"
                f"<td><span class='badge badge-info'>{c.protocol}</span></td>"
                f"<td>{_admin_badge if c.is_admin else _non_admin_badge}</td>"
                f"</tr>"
                for c in local_creds
            )
            parts.append(
                '<p style="color:#c9a96e;font-weight:600;margin-bottom:6px">🔑 Local Auth Credentials</p>'
                '<div class="table-wrapper" style="margin-bottom:12px"><table>'
                '<thead><tr><th>Username</th><th>Password</th><th>Protocol</th><th>Admin</th></tr></thead>'
                f'<tbody>{local_rows}</tbody></table></div>'
            )

        share_rows: list[str] = []
        for rec in history:
            if "--shares" not in rec.command or not rec.output.strip():
                continue
            for name, perms, remark in parse_nxc_shares(rec.output):
                badge = "badge-danger" if "WRITE" in perms else "badge-warning"
                share_rows.append(
                    f"<tr><td style='font-family:var(--font-mono)'>{name}</td>"
                    f"<td><span class='badge {badge}'>{perms}</span></td>"
                    f"<td style='color:var(--text-muted);font-size:12px'>{remark}</td></tr>"
                )
        if share_rows:
            parts.append(
                '<p style="color:var(--accent-gold);font-weight:600;margin-bottom:6px">Accessible SMB Shares</p>'
                '<div class="table-wrapper" style="margin-bottom:12px"><table>'
                '<thead><tr><th>Share</th><th>Permission</th><th>Remark</th></tr></thead>'
                f'<tbody>{"".join(share_rows)}</tbody></table></div>'
            )

        vuln_rows: list[str] = []
        for rec in history:
            if "vuln" not in rec.label.lower() or not rec.output.strip():
                continue
            for f in parse_nmap_vuln(rec.output):
                vuln_rows.append(
                    f"<tr><td><span class='port-tag high-value'>{f.port}/tcp</span></td>"
                    f"<td style='font-family:var(--font-mono);color:var(--danger)'>{f.script}</td>"
                    f"<td style='font-size:12px'>{f.detail[:200]}</td></tr>"
                )
        if vuln_rows:
            parts.append(
                '<p style="color:var(--danger);font-weight:600;margin-bottom:6px">Vulnerability Findings</p>'
                '<div class="table-wrapper" style="margin-bottom:12px"><table>'
                '<thead><tr><th>Port</th><th>Script</th><th>Detail</th></tr></thead>'
                f'<tbody>{"".join(vuln_rows)}</tbody></table></div>'
            )

        user_rows: list[str] = []
        for rec in history:
            if not any(k in rec.label.lower() for k in ("ldap", "smb users", "enum4linux")):
                continue
            parsed = parse_enum4linux(rec.output)
            for u in parsed.users:
                user_rows.append(
                    f"<tr><td style='font-family:var(--font-mono)'>{u}</td>"
                    f"<td style='color:var(--text-muted);font-size:12px'>{rec.label}</td></tr>"
                )
        if user_rows:
            parts.append(
                '<p style="color:var(--accent-sage);font-weight:600;margin-bottom:6px">Enumerated Users</p>'
                '<div class="table-wrapper" style="margin-bottom:12px"><table>'
                '<thead><tr><th>Username</th><th>Source</th></tr></thead>'
                f'<tbody>{"".join(user_rows)}</tbody></table></div>'
            )

        unauth_rows = _extract_unauth_rows(history)
        if unauth_rows:
            parts.append(
                '<p style="color:var(--danger);font-weight:600;margin-bottom:6px">'
                '🔓 Unauthenticated Access</p>'
                '<div class="table-wrapper" style="margin-bottom:12px"><table>'
                '<thead><tr><th>Service</th><th>Finding</th></tr></thead>'
                '<tbody>' + "".join(unauth_rows) + '</tbody></table></div>'
            )

        if not parts:
            return '<p class="empty-msg">No critical findings detected.</p>'
        return "".join(parts)

    def _cmd_blocks(self) -> str:
        if not self.session.command_history:
            return '<p class="empty-msg">No commands recorded.</p>'
        blocks = []
        for i, rec in enumerate(self.session.command_history):
            ts = rec.timestamp.strftime("%H:%M:%S")
            rc_badge = ('<span class="badge badge-success">rc=0</span>'
                        if rec.return_code == 0 else
                        f'<span class="badge badge-danger">rc={rec.return_code}</span>')
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rid = f"fr-{i}"
            blocks.append(
                f'<div style="margin-bottom:14px;border:1px solid var(--border);border-radius:8px">'
                f'<div class="code-header">'
                f'<span style="color:var(--accent-gold)">{rec.label or "Command"}</span>'
                f'<span style="display:flex;gap:8px;align-items:center">{rc_badge}'
                f'<span style="color:var(--text-muted)">{ts}</span>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{rid}\').value,this)">'
                f'{_COPY_ICON} Copy Output</button>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{rid}\').dataset.cmd,this)">'
                f'{_COPY_ICON} Copy Command</button></span></div>'
                f'<div class="code-block cmd-line">$ {rec.command}</div>'
                f'<textarea id="{rid}" style="display:none" data-cmd="{rec.command.replace(chr(34),chr(39))}">'
                f'{rec.output}</textarea>'
                f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>'
                f'</div>'
            )
        return "\n".join(blocks)


# ──────────────────────────────────────────────────────── ADReport

class ADReport:
    """HTML report for adenum (Active Directory enumeration) mode."""

    def __init__(self, console: Console, session: EnumSession, enumerator):
        self.console = console
        self.session = session
        self.enum = enumerator

    def generate(self, output_dir: str = ".", quiet: bool = False) -> str:
        out = Path(output_dir) / "adenum.html"
        out.write_text(self._build(), encoding="utf-8")
        if not quiet:
            self.console.print(
                Panel(
                    f"[bold #8b7aa8]AD Report:[/bold #8b7aa8] [#c0c8d4]{out}[/#c0c8d4]",
                    border_style="#8b7aa8",
                    padding=(0, 2),
                )
            )
        return str(out)

    def _build(self) -> str:
        import re as _re
        e = self.enum
        now = datetime.now()
        elapsed = now - self.session.started_at
        m_e, s_e = divmod(int(elapsed.total_seconds()), 60)

        tpl = (Path(__file__).parent / "template.html").read_text(encoding="utf-8")
        css_m = _re.search(r"<style>(.*?)</style>", tpl, _re.S)
        css = f"<style>{css_m.group(1)}</style>" if css_m else ""
        js_m = _re.search(r"<script>(.*?)</script>", tpl, _re.S)
        js = f"<script>{js_m.group(1)}</script>" if js_m else ""

        # Count kerberoast hashes (nxc writes directly to file)
        kerb_count = len(e.kerb_hashes)
        if not kerb_count and Path("kerb.hash").exists():
            kerb_count = sum(1 for ln in Path("kerb.hash").read_text(
                errors="replace").splitlines() if ln.strip().startswith("$krb5tgs$"))

        def _stat(value, label, cls=""):
            return (
                f'<div class="stat-card{" " + cls if cls else ""}">'
                f'<div class="stat-value">{value}</div>'
                f'<div class="stat-label">{label}</div>'
                f'</div>'
            )

        valid_count = len(e.valid_creds)
        admin_count = sum(1 for c in self.session.credentials if c.success and c.is_admin)
        total_ports = sum(len(h.open_ports) for h in self.session.hosts.values())
        stats_html = (
            '<div class="stats-grid">'
            + _stat(len(self.session.hosts), "Hosts", "info" if self.session.hosts else "")
            + _stat(total_ports, "Open Ports", "info" if total_ports else "")
            + _stat(len(e.users), "Users Found", "info" if e.users else "")
            + _stat(valid_count, "Valid Creds", "success" if valid_count else "")
            + _stat(admin_count, "Admin Creds", "danger" if admin_count else "")
            + _stat(len(e.asrep_hashes), "AS-REP Hashes", "danger" if e.asrep_hashes else "")
            + _stat(kerb_count, "Kerberoast", "danger" if kerb_count else "")
            + _stat(len(e.laps_passwords), "LAPS Pwds", "success" if e.laps_passwords else "")
            + _stat(len(self.session.command_history), "Commands Run")
            + '</div>'
        )

        domain_info = []
        if e.domain:
            domain_info.append(
                f'<span style="color:var(--accent-sage)">Domain:</span> '
                f'<code style="background:#161b22;padding:2px 7px;border-radius:4px">{e.domain}</code>'
            )
        if e.dc_ip:
            dc_host = self.session.hosts.get(e.dc_ip)
            dc_name = dc_host.display_name if dc_host else e.dc_ip
            domain_info.append(
                f'<span style="color:var(--text-muted)">DC:</span> '
                f'<code style="background:#161b22;padding:2px 7px;border-radius:4px">'
                f'{e.dc_ip} ({dc_name})</code>'
            )
        if e.valid_creds:
            cred_strs = [c.display() for c in e.valid_creds[:3]]
            if len(e.valid_creds) > 3:
                cred_strs.append(f"+{len(e.valid_creds) - 3} more")
            domain_info.append(
                f'<span style="color:var(--text-muted)">Valid Creds ({len(e.valid_creds)}):</span> '
                f'<code style="background:#161b22;padding:2px 7px;border-radius:4px">'
                f'{" · ".join(cred_strs)}</code>'
            )
        elif e.usernames:
            domain_info.append(
                f'<span style="color:var(--text-muted)">Users tested:</span> '
                f'<code style="background:#161b22;padding:2px 7px;border-radius:4px">'
                f'{len(e.usernames)} user(s)</code>'
            )

        overview_content = stats_html
        if domain_info:
            overview_content += (
                '<div class="card" style="margin-top:0">'
                '<div class="card-header"><div class="card-title">Environment</div></div>'
                '<div style="display:flex;flex-wrap:wrap;gap:16px;font-size:12px;padding:6px 8px">'
                + "".join(f'<span>{p}</span>' for p in domain_info)
                + '</div></div>'
            )

        # Reuse ReportGenerator helpers for the shared recon sections so adenum
        # contains everything focus/drill produce (hosts, ports, critical, web…)
        rg = ReportGenerator(self.console, self.session)

        # Build all sections
        hosts_html      = self._hosts_table(rg)
        _ports_md = rg._md_port_summary().replace("&", "&amp;").replace("<", "&lt;")
        ports_html      = (
            '<div class="card"><div class="card-header" style="display:flex;'
            'align-items:center;justify-content:space-between">'
            '<div class="card-title">Port Summary</div>'
            '<button class="copy-btn" onclick="copyMd(\'ad-md-ports\')">📋 Copy Markdown</button>'
            '</div>'
            f'<textarea id="ad-md-ports" style="display:none">{_ports_md}</textarea></div>'
            + rg._heatmap_html()
        )
        critical_html   = rg._critical_html()
        services_html   = self._services_section()
        web_html        = rg._http_links_html()
        matrix_html     = rg._matrix_html()
        users_section   = self._users_section()
        creds_section   = self._creds_section()
        passpol_section = self._passpol_section()
        asrep_section   = self._asrep_section()
        kerb_section    = self._kerb_section()
        laps_section    = self._laps_section()
        files_section   = self._output_files_section()
        cmd_blocks      = self._cmd_blocks()

        has_hosts    = bool(self.session.hosts)
        has_critical = "No critical findings" not in critical_html
        has_web      = "No HTTP services" not in web_html
        has_matrix   = "No credential data" not in matrix_html

        domain_str = e.domain or "unknown domain"
        dc_str = e.dc_ip or "?"

        sections_html = (
            self._section("overview", "Overview",
                          f"{dc_str} · {m_e}m{s_e:02d}s", overview_content)
            + (self._section("hosts", "Hosts",
                             f"{len(self.session.hosts)} host(s) · {total_ports} open port(s)",
                             hosts_html) if hosts_html else "")
            + (self._section_raw("ports", "Port Map",
                             "open ports across all hosts", ports_html)
               if has_hosts else "")
            + (self._section_raw("critical", "Critical Findings",
                             "shares · vulns · unauthenticated access", critical_html)
               if has_critical else "")
            + (self._section_raw("services", "Service Enumeration",
                             "per-host deep enumeration (focus-style)", services_html)
               if services_html else "")
            + (self._section("web", "Web Services",
                             "HTTP/HTTPS endpoints",
                             f'<div style="padding:10px 14px;display:flex;'
                             f'flex-direction:column;gap:4px">{web_html}</div>')
               if has_web else "")
            + (self._section("users", "AD Users",
                             f"{len(e.users)} user(s) enumerated", users_section)
               if users_section else "")
            + (self._section("creds", "Valid Credentials",
                             f"{valid_count} credential(s) — spray results", creds_section)
               if creds_section else "")
            + (self._section_raw("matrix", "Credential Matrix",
                             "valid creds × hosts access map",
                             f'<div class="card">{matrix_html}</div>')
               if has_matrix else "")
            + (self._section("passpol", "Password Policy",
                             "lockout · complexity · length", passpol_section)
               if passpol_section else "")
            + (self._section("asrep", "AS-REP Roasting",
                             f"{len(e.asrep_hashes)} hash(es) — hashcat -m 18200", asrep_section)
               if asrep_section else "")
            + (self._section("kerb", "Kerberoasting",
                             f"{kerb_count} hash(es) — hashcat -m 13100", kerb_section)
               if kerb_section else "")
            + (self._section("laps", "LAPS Passwords",
                             f"{len(e.laps_passwords)} machine(s)", laps_section)
               if e.laps_passwords else "")
            + (self._section("files", "Output Files",
                             "hashes · bloodhound · ldapbooks", files_section)
               if files_section else "")
            + self._section("commands", "Command Log",
                            f"{len(self.session.command_history)} commands", cmd_blocks)
            + self._section_raw("checklist", "OSCP チェックリスト",
                            "チェックボックスで進捗管理 · 項目を開くと具体コマンド",
                            '<div class="card"><div style="padding:4px 16px 14px">'
                            + checklist_html() + '</div></div>')
        )

        nav_defs = [
            ("overview", "🏠 Overview", True),
            ("hosts",    "🖥 Hosts",      bool(hosts_html)),
            ("ports",    "🔌 Ports",      has_hosts),
            ("critical", "🔥 Critical",   has_critical),
            ("services", "🛠 Services",   bool(services_html)),
            ("web",      "🌐 Web",        has_web),
            ("users",    "👤 Users",      bool(users_section)),
            ("creds",    "🔑 Creds",      bool(creds_section)),
            ("matrix",   "🔲 Matrix",     has_matrix),
            ("passpol",  "📜 Policy",     bool(passpol_section)),
            ("asrep",    "⚡ AS-REP",      bool(asrep_section)),
            ("kerb",     "🎫 Kerberoast", bool(kerb_section)),
            ("laps",     "🔐 LAPS",       bool(e.laps_passwords)),
            ("files",    "📂 Files",      bool(files_section)),
            ("commands", "📋 Commands",   True),
            ("checklist", "✅ Checklist", True),
        ]
        nav_btns = "".join(
            f'<button class="nav-item" onclick="show(\'{sid}\',this)">{label}</button>'
            for sid, label, present in nav_defs if present
        )

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxenum adenum — {domain_str}</title>
{css}
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo" style="color:#8b7aa8">◈ adenum</div>
      <div class="sidebar-subtitle" style="font-family:monospace;font-size:12px;color:var(--accent-silver)">{domain_str}</div>
      <div class="sidebar-subtitle" style="margin-top:2px;font-family:monospace;font-size:11px">DC: {dc_str}</div>
    </div>
    <div class="sidebar-nav">
      <div class="nav-section">Navigation</div>
      {nav_btns}
    </div>
  </nav>
  <div class="main">
    <div class="topbar">
      <div class="topbar-title" style="color:#8b7aa8">◈ Active Directory Enumeration
        <span style="font-size:12px;font-weight:400;color:var(--text-muted);margin-left:10px;font-family:monospace">{domain_str}</span>
      </div>
      <div style="display:flex;align-items:center;gap:12px">
        <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">☀ Light</button>
        <span class="topbar-meta">{now.strftime("%Y-%m-%d %H:%M")} &nbsp;·&nbsp; {m_e}m{s_e:02d}s &nbsp;·&nbsp; proxenum v2.2.0</span>
      </div>
    </div>
    <div class="content">
      {sections_html}
    </div>
  </div>
</div>
{js}
<script>
document.addEventListener('DOMContentLoaded', () => {{
  const first = document.querySelector('.nav-item');
  if (first) first.click();
}});
</script>
</body>
</html>"""

    def _section(self, sid: str, title: str, desc: str, content: str) -> str:
        return (
            f'<div class="section" id="section-{sid}">'
            f'<div class="section-header">'
            f'<div class="section-title">{title}</div>'
            f'<div class="section-desc">{desc}</div>'
            f'</div>'
            f'<div class="card">{content}</div>'
            f'</div>'
        )

    def _section_raw(self, sid: str, title: str, desc: str, content: str) -> str:
        """Like _section but does not wrap content in a card (content provides its own)."""
        return (
            f'<div class="section" id="section-{sid}">'
            f'<div class="section-header">'
            f'<div class="section-title">{title}</div>'
            f'<div class="section-desc">{desc}</div>'
            f'</div>'
            f'{content}'
            f'</div>'
        )

    def _hosts_table(self, rg: "ReportGenerator") -> str:
        if not self.session.hosts:
            return ""
        rows = rg._host_rows_summary()
        md = (rg._md_hosts() + "\n\n" + rg._md_ports()).replace("&", "&amp;").replace("<", "&lt;")
        return (
            '<div class="card-header" style="padding:10px 16px 8px;border-bottom:1px solid var(--border);'
            'display:flex;align-items:center;justify-content:space-between">'
            '<div class="card-title">Inventory</div>'
            '<button class="copy-btn" onclick="copyMd(\'ad-md-hosts\')">📋 Copy Markdown</button>'
            '</div>'
            f'<textarea id="ad-md-hosts" style="display:none">{md}</textarea>'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>IP</th><th>Hostname</th><th>FQDN</th><th>OS</th>'
            '<th>Domain</th><th>SMB Signing</th><th>Open Ports</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    # Labels handled by dedicated sections / shown elsewhere — kept out of the
    # services "Other output" catch-all so it doesn't echo AD or scan noise.
    # Pure port-discovery labels (just port lists) — their content is already
    # in the Ports section. "Nmap detail" (-sCV, version/script output) is NOT
    # listed here so it still surfaces (collapsed) under "Other Service Output".
    _SVC_SCAN_KW = ("rustscan", "nmap -p-", "nmap scan", "nmap full", "nmap top")
    _SVC_AD_KW = (
        "getnpusers", "hashcat", "spray", "gpp_", "gpp ", " laps", "ldapdomaindump",
        "bloodhound", "secretsdump", "kerberoast", "rid-brute", "pass-pol",
        "enumdomusers", "enumdomgroups", "getdompwinfo", "host-info",
        "users-anon", "users (auth)", " auth ", "rpcclient enum", "hydra",
    )
    _SVC_STRUCTURED_KW = ("feroxbuster", "whatweb", "ffuf", "curl", "davtest",
                          "searchsploit", "enum4linux", "snmp", "onesixtyone",
                          "vuln", "udp")

    def _host_scoped_session(self, ip: str, host: "Host") -> "EnumSession":
        """A session view containing only one host and the command records that
        target its IP — lets the single-host FocusReport parsers run per host
        without bleeding output from other targets into the report."""
        import re as _re
        sub = EnumSession()
        sub.hosts = {ip: host}
        sub.domain = self.session.domain
        sub.started_at = self.session.started_at
        sub.credentials = self.session.credentials
        sub.web_exts = self.session.web_exts
        # Whole-IP match so 10.0.0.1 does not also pick up 10.0.0.10
        pat = _re.compile(rf"(?<!\d){_re.escape(ip)}(?!\d)")
        sub.command_history = [r for r in self.session.command_history
                               if pat.search(r.command)]
        return sub

    @staticmethod
    def _subsection(title: str, body: str) -> str:
        if not body or not body.strip():
            return ""
        return (
            '<div style="margin:10px 0 4px">'
            f'<div style="color:var(--accent-gold);font-weight:600;font-size:13px;'
            f'margin:6px 2px">{title}</div>'
            f'{body}</div>'
        )

    def _smb_shares_html(self, sub: "EnumSession", ip: str) -> str:
        """Render authenticated SMB share results (per user) as tables."""
        recs = [r for r in sub.command_history
                if ("--shares" in r.command or "shares" in r.label.lower())
                and r.output.strip()]
        blocks = []
        for r in recs:
            shares = parse_nxc_shares(r.output)
            if not shares:
                continue
            # Label form: "SMB shares user@ip" → surface the user
            who = r.label.replace("SMB shares ", "").strip() or r.label
            rows = ""
            for name, perms, remark in shares:
                pcol = ("#7aab7a" if "WRITE" in perms else
                        "#58a6ff" if "READ" in perms else "var(--text-muted)")
                rows += (
                    f'<tr><td style="font-family:var(--font-mono)">{name}</td>'
                    f'<td><span style="color:{pcol};font-family:var(--font-mono);'
                    f'font-size:11px">{perms}</span></td>'
                    f'<td style="font-size:11px;color:var(--text-muted)">{remark}</td></tr>'
                )
            blocks.append(
                f'<div style="font-size:11px;color:var(--text-muted);margin:4px 2px">'
                f'as <code style="color:var(--accent-sage)">{who}</code></div>'
                '<div class="table-wrapper" style="margin-bottom:8px"><table>'
                '<thead><tr><th>Share</th><th>Access</th><th>Remark</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>'
            )
        return "".join(blocks)

    def _other_services_html(self, sub: "EnumSession", ip: str) -> str:
        """Readable collapsibles for service records not covered by a structured
        parser (ftp, ssh, mysql, redis, rpc, ldap banners…). De-duplicates by
        label and skips scan/AD-phase noise that lives in other sections."""
        seen: set[str] = set()
        blocks = []
        for r in sub.command_history:
            if not r.output.strip():
                continue
            lab = (r.label or r.command).lower()
            if any(k in lab for k in self._SVC_SCAN_KW):
                continue
            if any(k in lab for k in self._SVC_AD_KW):
                continue
            if any(k in lab for k in self._SVC_STRUCTURED_KW):
                continue
            if "--shares" in r.command or "shares" in lab:
                continue
            key = r.label or r.command[:60]
            if key in seen:
                continue
            seen.add(key)
            safe = (r.output.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;"))
            rc_col = "#7aab7a" if r.return_code == 0 else "#f85149"
            blocks.append(
                '<details style="margin:6px 0;border:1px solid var(--border);border-radius:6px">'
                '<summary style="cursor:pointer;padding:6px 10px;font-family:monospace;'
                f'font-size:12px;color:{rc_col}">{r.label or r.command[:60]}</summary>'
                '<div class="code-block output-block" style="margin:0">'
                f'<code>{safe[:5000]}</code></div>'
                '</details>'
            )
        return "".join(blocks)

    def _services_section(self) -> str:
        """Per-host deep-enumeration view: port chips + structured parsed output
        (web file tree, vuln findings, SMB shares, SNMP, enum4linux) reusing the
        focus-mode parsers, plus a readable catch-all for everything else."""
        if not self.session.hosts:
            return ""
        parts: list[str] = []
        for ip, host in sorted(self.session.hosts.items()):
            if not host.open_ports:
                continue
            sub = self._host_scoped_session(ip, host)
            fr = FocusReport(self.console, sub, ip)

            chips = ""
            for p, svc in sorted(host.open_ports.items()):
                col = "#c9a96e" if p in HIGH_VALUE_PORTS else "#58a6ff"
                chips += (
                    f'<span style="display:inline-block;font-family:monospace;font-size:11px;'
                    f'padding:2px 7px;margin:2px;border-radius:12px;background:{col}18;'
                    f'border:1px solid {col}44;color:{col}">{p}/{svc}</span>'
                )

            body = ""
            try:
                vuln = fr._vuln_html()
                if vuln and "No vulnerabilities detected" not in vuln:
                    body += self._subsection("🔥 Vulnerability Scan", vuln)
            except Exception:
                pass
            try:
                body += self._subsection("📁 SMB Shares", self._smb_shares_html(sub, ip))
            except Exception:
                pass
            try:
                body += self._subsection("🪟 enum4linux", fr._enum4linux_html())
            except Exception:
                pass
            try:
                body += self._subsection("🌐 Web Content", fr._http_html())
            except Exception:
                pass
            try:
                body += self._subsection("📡 SNMP", fr._snmp_html())
            except Exception:
                pass
            try:
                body += self._subsection("📨 UDP", fr._udp_html())
            except Exception:
                pass
            try:
                body += self._subsection("⋯ Other Service Output",
                                         self._other_services_html(sub, ip))
            except Exception:
                pass

            if not body.strip():
                body = '<p class="empty-msg">No service enumeration output yet.</p>'

            name = host.display_name if host.display_name != ip else ip
            parts.append(
                f'<div class="card">'
                f'<div class="card-header"><div class="card-title">{name} '
                f'<span style="color:var(--text-muted);font-size:12px;'
                f'font-family:monospace">{ip}</span></div></div>'
                f'<div style="padding:6px 12px 2px">{chips}</div>'
                f'<div style="padding:4px 12px 10px">{body}</div>'
                f'</div>'
            )
        return "\n".join(parts)

    def _creds_section(self) -> str:
        """Table of all spray/matrix results (successful + failed) grouped by success."""
        successes = [c for c in self.session.credentials if c.success]
        if not successes:
            return ""
        rows = ""
        for c in successes:
            h = self.session.hosts.get(c.ip)
            name = h.display_name if h else c.ip
            is_local = getattr(c, "local_auth", False)
            auth_badge = (
                '<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                'background:#c9a96e22;border:1px solid #c9a96e55;color:#c9a96e">LOCAL</span>'
                if is_local else
                '<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                'background:#7aab7a22;border:1px solid #7aab7a55;color:#7aab7a">DOMAIN</span>'
            )
            admin_badge = (
                '<span style="font-size:10px;padding:2px 6px;border-radius:8px;'
                'background:#c9a96e22;border:1px solid #c9a96e55;color:#c9a96e">👑 Admin</span>'
                if c.is_admin else
                '<span style="color:var(--text-muted)">—</span>'
            )
            secret = (
                f'<span style="color:var(--text-muted);font-size:10px">[NTLM] {c.password[:16]}…</span>'
                if c.is_ntlm else
                f'<span style="font-family:var(--font-mono);color:var(--accent-gold)">{c.password}</span>'
            )
            proto_badge = (
                f'<span style="font-size:10px;padding:1px 5px;border-radius:8px;'
                f'background:#58a6ff22;border:1px solid #58a6ff55;color:#58a6ff">{c.protocol}</span>'
            )
            rows += (
                f'<tr>'
                f'<td>{proto_badge}</td>'
                f'<td style="font-family:var(--font-mono);font-size:12px">{name}</td>'
                f'<td class="td-ip">{c.ip}</td>'
                f'<td style="font-family:var(--font-mono)">{c.username}</td>'
                f'<td>{secret}</td>'
                f'<td>{auth_badge}</td>'
                f'<td>{admin_badge}</td>'
                f'</tr>'
            )
        return (
            '<div class="card-header" style="padding:10px 16px 8px;border-bottom:1px solid var(--border);'
            'display:flex;align-items:center;justify-content:space-between">'
            f'<div class="card-title" style="color:#7aab7a">✓ {len(successes)} Valid Credential(s)</div>'
            '</div>'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>Proto</th><th>Host</th><th>IP</th><th>Username</th>'
            '<th>Password / Hash</th><th>Auth</th><th>Admin</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _passpol_section(self) -> str:
        e = self.enum
        text = getattr(e, "pass_pol_text", "") or ""
        thr = getattr(e, "lockout_threshold", None)
        if not text and thr is None:
            return ""
        rows = ""
        for ln in text.splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                rows += (
                    f'<tr><td style="color:var(--text-secondary)">{k.strip()}</td>'
                    f'<td style="font-family:var(--font-mono);color:var(--accent-gold)">'
                    f'{v.strip()}</td></tr>'
                )
            elif ln.strip():
                rows += f'<tr><td colspan="2">{ln.strip()}</td></tr>'
        table = (
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>Setting</th><th>Value</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        ) if rows else ""
        banner = ""
        if thr is not None:
            if thr == 0:
                banner = (
                    '<div style="padding:10px 14px;color:#7aab7a">'
                    'Account lockout threshold: <strong>None (0)</strong> '
                    '— password spraying is safe.</div>'
                )
            else:
                banner = (
                    f'<div style="padding:10px 14px;color:#f85149">⚠ Account lockout '
                    f'threshold: <strong>{thr}</strong> — limit spray attempts per '
                    f'account to avoid lockout.</div>'
                )
        return banner + table

    def _users_section(self) -> str:
        e = self.enum
        if not e.users:
            return ""
        sorted_users = sorted(e.users, key=str.lower)
        rows = "".join(
            f'<tr><td style="font-family:var(--font-mono)">{u}</td></tr>'
            for u in sorted_users
        )
        users_txt = "\n".join(sorted_users)
        users_esc = users_txt.replace("&", "&amp;").replace("<", "&lt;")
        uid = "adenum-users"
        return (
            '<div class="card-header" style="padding:10px 16px 8px;border-bottom:1px solid var(--border);'
            'display:flex;align-items:center;justify-content:space-between">'
            f'<div class="card-title">{len(e.users)} Domain User(s)</div>'
            f'<button class="copy-btn" onclick="copyMd(\'{uid}\')">📋 Copy as users.txt</button>'
            '</div>'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>Username</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
            f'<pre id="{uid}" style="display:none">{users_esc}</pre>'
        )

    def _asrep_section(self) -> str:
        e = self.enum
        hashes = list(e.asrep_hashes)
        if not hashes and Path("asrep.hash").exists():
            hashes = [ln.strip() for ln in Path("asrep.hash").read_text(
                errors="replace").splitlines() if ln.strip().startswith("$krb5asrep$")]
        if not hashes:
            return ""

        import re as _re
        hashcat_cmd = "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt"
        uid = "adenum-asrep"
        hashes_esc = "\n".join(hashes).replace("&", "&amp;").replace("<", "&lt;")

        rows = ""
        for h in hashes:
            m = _re.match(r"\$krb5asrep\$\d+\$([^$@]+)", h)
            user = m.group(1) if m else "?"
            trunc = h[:88] + ("…" if len(h) > 88 else "")
            rows += (
                f'<tr>'
                f'<td style="font-family:var(--font-mono);font-size:11px;color:#c9a96e">{user}</td>'
                f'<td style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);'
                f'word-break:break-all">{trunc}</td>'
                f'</tr>'
            )

        return (
            '<div class="card-header" style="padding:10px 16px 8px;border-bottom:1px solid var(--border);'
            'display:flex;align-items:center;justify-content:space-between">'
            f'<div class="card-title" style="color:#f85149">⚠ {len(hashes)} AS-REP Roastable Account(s)</div>'
            f'<button class="copy-btn" onclick="copyMd(\'{uid}\')">📋 Copy Hashes</button>'
            '</div>'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>User</th><th>Hash (truncated)</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
            '<div style="padding:8px 14px 10px">'
            '<div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Crack with hashcat:</div>'
            f'<div class="code-block cmd-line" style="font-size:11px">$ {hashcat_cmd}</div>'
            '</div>'
            f'<pre id="{uid}" style="display:none">{hashes_esc}</pre>'
        )

    def _kerb_section(self) -> str:
        e = self.enum
        hashes = list(e.kerb_hashes)
        if not hashes and Path("kerb.hash").exists():
            hashes = [ln.strip() for ln in Path("kerb.hash").read_text(
                errors="replace").splitlines() if ln.strip().startswith("$krb5tgs$")]
        if not hashes:
            return ""

        import re as _re
        hashcat_cmd = "hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt"
        uid = "adenum-kerb"
        hashes_esc = "\n".join(hashes).replace("&", "&amp;").replace("<", "&lt;")

        rows = ""
        for h in hashes:
            m = _re.match(r"\$krb5tgs\$\d+\$\*([^$]+)\$[^$]+\$([^*]+)\*", h)
            user = m.group(1) if m else "?"
            spn  = m.group(2) if m else "?"
            trunc = h[:80] + ("…" if len(h) > 80 else "")
            rows += (
                f'<tr>'
                f'<td style="font-family:var(--font-mono);font-size:11px;color:#7aab7a">{user}</td>'
                f'<td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">{spn}</td>'
                f'<td style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);'
                f'word-break:break-all">{trunc}</td>'
                f'</tr>'
            )

        return (
            '<div class="card-header" style="padding:10px 16px 8px;border-bottom:1px solid var(--border);'
            'display:flex;align-items:center;justify-content:space-between">'
            f'<div class="card-title" style="color:#f85149">⚠ {len(hashes)} Kerberoastable Service(s)</div>'
            f'<button class="copy-btn" onclick="copyMd(\'{uid}\')">📋 Copy Hashes</button>'
            '</div>'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>User</th><th>SPN</th><th>Hash (truncated)</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
            '<div style="padding:8px 14px 10px">'
            '<div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Crack with hashcat:</div>'
            f'<div class="code-block cmd-line" style="font-size:11px">$ {hashcat_cmd}</div>'
            '</div>'
            f'<pre id="{uid}" style="display:none">{hashes_esc}</pre>'
        )

    def _laps_section(self) -> str:
        e = self.enum
        if not e.laps_passwords:
            return ""
        rows = ""
        for machine, pw in e.laps_passwords:
            pw_esc = pw.replace("&", "&amp;").replace("<", "&lt;")
            rows += (
                f'<tr>'
                f'<td style="font-family:var(--font-mono)">{machine}</td>'
                f'<td style="font-family:var(--font-mono);color:var(--accent-gold)">{pw_esc}</td>'
                f'<td><button class="copy-btn" onclick="copyText(\'{pw_esc}\',this)">'
                f'{_COPY_ICON} Copy</button></td>'
                f'</tr>'
            )
        return (
            '<div style="padding:8px 14px">'
            '<div class="table-wrapper"><table>'
            '<thead><tr><th>Machine</th><th>LAPS Password</th><th></th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
            '</div>'
        )

    def _output_files_section(self) -> str:
        e = self.enum
        parts = []

        # Hash and wordlist files in cwd
        for fname, color, desc in [
            ("asrep.hash",    "#f85149", "AS-REP hashes → hashcat -m 18200"),
            ("kerb.hash",     "#f85149", "Kerberoast hashes → hashcat -m 13100"),
            ("users.txt",     "#7aab7a", "Domain user list"),
            ("passwords.txt", "#c9a96e", "Cracked passwords"),
            ("ntlmhash.txt",  "#8b7aa8", "NT hashes for PTH"),
        ]:
            p = Path(fname)
            if not p.exists():
                continue
            try:
                count = sum(1 for ln in p.read_text(errors="replace").splitlines() if ln.strip())
                size = p.stat().st_size
            except Exception:
                count, size = 0, 0
            parts.append(
                f'<div style="display:flex;align-items:center;gap:10px;padding:5px 0;'
                f'border-bottom:1px solid var(--border)">'
                f'<span style="font-family:var(--font-mono);font-size:12px;color:{color};min-width:140px">{fname}</span>'
                f'<span style="font-size:11px;color:var(--text-muted)">{count} lines · {size:,}B</span>'
                f'<span style="font-size:11px;color:var(--text-muted);margin-left:auto">{desc}</span>'
                f'</div>'
            )

        # Per-user output directories (BloodHound JSON / ldapdomaindump)
        import re as _reuser
        seen_users: set[str] = set()
        for c in e.valid_creds:
            uname = c.username.replace("\\", "/").split("/")[-1]
            safe = _reuser.sub(r"[^A-Za-z0-9._@-]", "_", uname).strip("_") or "user"
            if safe in seen_users:
                continue
            seen_users.add(safe)
            for sub_name, color, desc in [
                ("adenum",    "#c9a96e", f"BloodHound JSON ({safe}) — cat {safe}/adenum/*_users.json | jq"),
                ("ldapbooks", "#58a6ff", f"ldapdomaindump output ({safe})"),
            ]:
                sub_dir = Path(safe) / sub_name
                if not sub_dir.exists():
                    continue
                try:
                    files = [f for f in sub_dir.iterdir() if f.is_file()]
                    file_count = len(files)
                    jsons = [f for f in files if f.suffix == ".json"]
                    extra = f" · {len(jsons)} json" if jsons else ""
                except Exception:
                    file_count, extra = 0, ""
                parts.append(
                    f'<div style="display:flex;align-items:center;gap:10px;padding:5px 0;'
                    f'border-bottom:1px solid var(--border)">'
                    f'<span style="font-family:var(--font-mono);font-size:12px;color:{color}">'
                    f'{safe}/{sub_name}/</span>'
                    f'<span style="font-size:11px;color:var(--text-muted)">'
                    f'{file_count} files{extra}</span>'
                    f'<span style="font-size:11px;color:var(--text-muted);margin-left:auto">{desc}</span>'
                    f'</div>'
                )

        if not parts:
            return ""
        return (
            '<div style="padding:10px 16px;font-size:12px">'
            + "\n".join(parts)
            + '</div>'
        )

    def _cmd_blocks(self) -> str:
        if not self.session.command_history:
            return '<p class="empty-msg">No commands recorded.</p>'
        blocks = []
        for i, rec in enumerate(self.session.command_history):
            ts = rec.timestamp.strftime("%H:%M:%S")
            rc_badge = ('<span class="badge badge-success">rc=0</span>'
                        if rec.return_code == 0 else
                        f'<span class="badge badge-danger">rc={rec.return_code}</span>')
            safe = rec.output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rid = f"ad-cmd-{i}"
            blocks.append(
                f'<div style="margin-bottom:14px;border:1px solid var(--border);border-radius:8px">'
                f'<div class="code-header">'
                f'<span style="color:var(--accent-gold)">{rec.label or "Command"}</span>'
                f'<span style="display:flex;gap:8px;align-items:center">{rc_badge}'
                f'<span style="color:var(--text-muted)">{ts}</span>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{rid}\').value,this)">'
                f'{_COPY_ICON} Copy Output</button>'
                f'<button class="copy-btn" onclick="copyText(document.getElementById(\'{rid}\').dataset.cmd,this)">'
                f'{_COPY_ICON} Copy Command</button></span></div>'
                f'<div class="code-block cmd-line">$ {rec.command}</div>'
                f'<textarea id="{rid}" style="display:none" data-cmd="{rec.command.replace(chr(34),chr(39))}">'
                f'{rec.output}</textarea>'
                f'<div class="code-block output-block"><code>{safe or "(no output)"}</code></div>'
                f'</div>'
            )
        return "\n".join(blocks)


# ------------------------------------------------------------------ helpers

import re as _re

_UNAUTH_PATTERNS = [
    # nxc ftp anonymous success
    (r"nxc\s+ftp\s+(\S+)", r"\[\+\].*[Aa]nonymous", "FTP", "Anonymous login allowed"),
    # nxc ftp [+] with user anonymous
    (r"ftp.*?(\d+\.\d+\.\d+\.\d+)", r"\[\+\]", "FTP", "Authentication succeeded"),
    # nmap Anonymous FTP
    (r"(\d+\.\d+\.\d+\.\d+)", r"Anonymous FTP login allowed", "FTP", "Anonymous FTP login allowed"),
    # redis-cli PONG
    (r"redis.*?(\d+\.\d+\.\d+\.\d+)", r"^\+PONG|^PONG", "Redis", "Unauthenticated access (PONG)"),
    # nxc mysql [+] unauthenticated
    (r"nxc\s+mysql\s+(\S+)", r"\[\+\].*root|Anonymous", "MySQL", "Unauthenticated root access"),
    # nxc postgres [+]
    (r"nxc\s+postgres\s+(\S+)", r"\[\+\]", "PostgreSQL", "Unauthenticated access"),
    # nmap ftp-anon script
    (r"(\d+\.\d+\.\d+\.\d+)", r"ftp-anon:.*allowed", "FTP", "nmap ftp-anon script confirmed"),
]


def _extract_unauth_rows(history: list) -> list[str]:
    rows: list[str] = []
    seen: set[tuple] = set()
    for rec in history:
        cmd, out = rec.command, rec.output
        ip_m = _re.search(r"(\d+\.\d+\.\d+\.\d+)", cmd)
        src_ip = ip_m.group(1) if ip_m else "?"
        for cmd_pat, out_pat, svc, finding in _UNAUTH_PATTERNS:
            if not _re.search(cmd_pat, cmd, _re.I):
                continue
            if not _re.search(out_pat, out, _re.I | _re.M):
                continue
            key = (src_ip, svc)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                f"<tr><td class='td-ip'>{src_ip}</td>"
                f"<td><span class='badge badge-danger'>{svc}</span></td>"
                f"<td style='color:var(--danger)'>{finding}</td></tr>"
            )
    return rows


def _no_data(cols: int) -> str:
    return f'<tr><td colspan="{cols}" class="empty-msg">No data</td></tr>'


def _load_template() -> str:
    return (Path(__file__).parent / "template.html").read_text(encoding="utf-8")


class SprayReport:
    """Compact report for `spray` mode — credentialed service results per user."""

    def __init__(self, console: Console, session: EnumSession, sprayer):
        self.console = console
        self.session = session
        self.spray = sprayer

    def generate(self, output_dir: str = "spray", quiet: bool = False) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        out = Path(output_dir) / "spray.html"
        out.write_text(self._build(), encoding="utf-8")
        if not quiet:
            self.console.print(
                Panel(f"[bold #c9a96e]Spray Report:[/bold #c9a96e] [#c0c8d4]{out}[/#c0c8d4]",
                      border_style="#c9a96e", padding=(0, 2)))
        return str(out)

    def _build(self) -> str:
        import re as _re
        now = datetime.now()
        tpl = _load_template()
        css = (f"<style>{_re.search(r'<style>(.*?)</style>', tpl, _re.S).group(1)}</style>"
               if _re.search(r"<style>(.*?)</style>", tpl, _re.S) else "")
        js = (f"<script>{_re.search(r'<script>(.*?)</script>', tpl, _re.S).group(1)}</script>"
              if _re.search(r"<script>(.*?)</script>", tpl, _re.S) else "")

        findings = self.spray.findings
        hits = [f for f in findings if f[3]]

        # Per-user grouped results
        users: dict[str, list] = {}
        for cred, ip, service, success, is_admin, outfile in findings:
            users.setdefault(cred.username, []).append((ip, service, success, is_admin, outfile))

        user_cards = []
        for uname, rows in sorted(users.items()):
            row_html = ""
            for ip, service, success, is_admin, outfile in sorted(rows):
                if success:
                    badge = ('<span style="color:#c9a96e">👑 Pwn3d!</span>' if is_admin
                             else '<span style="color:#7aab7a">✓ access</span>')
                else:
                    badge = '<span style="color:var(--text-muted)">—</span>'
                loot = (f'<code style="font-size:10px;color:var(--accent-sage)">{outfile}</code>'
                        if outfile else '')
                row_html += (
                    f'<tr><td class="td-ip">{ip}</td>'
                    f'<td style="font-family:var(--font-mono)">{service.upper()}</td>'
                    f'<td>{badge}</td><td>{loot}</td></tr>'
                )
            n_ok = sum(1 for r in rows if r[2])
            user_cards.append(
                f'<div class="section" id="section-u-{_re.sub(chr(92)+"W","_",uname)}">'
                f'<div class="section-header"><div class="section-title">👤 {uname}</div>'
                f'<div class="section-desc">{n_ok}/{len(rows)} service(s) accepted · loot → spray/{uname}/</div></div>'
                f'<div class="card"><div class="table-wrapper"><table>'
                f'<thead><tr><th>IP</th><th>Service</th><th>Result</th><th>Loot file</th></tr></thead>'
                f'<tbody>{row_html or _no_data(4)}</tbody></table></div></div></div>'
            )

        overview = (
            '<div class="stats-grid">'
            f'<div class="stat-card"><div class="stat-value">{len(users)}</div><div class="stat-label">Users</div></div>'
            f'<div class="stat-card"><div class="stat-value">{len(self.spray.ips)}</div><div class="stat-label">Targets</div></div>'
            f'<div class="stat-card{" success" if hits else ""}"><div class="stat-value">{len(hits)}</div>'
            '<div class="stat-label">Cred Access</div></div>'
            f'<div class="stat-card{" danger" if any(h[4] for h in hits) else ""}">'
            f'<div class="stat-value">{sum(1 for h in hits if h[4])}</div><div class="stat-label">Admin</div></div>'
            '</div>'
        )

        sections = (
            f'<div class="section" id="section-overview"><div class="section-header">'
            f'<div class="section-title">Overview</div><div class="section-desc">'
            f'credentialed sweep — no deep enumeration</div></div>'
            f'<div class="card">{overview}</div></div>'
            + "".join(user_cards)
            + '<div class="section" id="section-checklist"><div class="section-header">'
            '<div class="section-title">OSCP チェックリスト</div>'
            '<div class="section-desc">チェックボックスで進捗管理 · 項目を開くと具体コマンド</div></div>'
            '<div class="card"><div style="padding:4px 16px 14px">' + checklist_html() + '</div></div></div>'
        )

        nav = (
            '<button class="nav-item" onclick="show(\'overview\',this)">🏠 Overview</button>'
            + "".join(
                f'<button class="nav-item" onclick="show(\'u-{_re.sub(chr(92)+"W","_",u)}\',this)">👤 {u}</button>'
                for u in sorted(users))
            + '<button class="nav-item" onclick="show(\'checklist\',this)">✅ Checklist</button>'
        )

        return f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxenum spray</title>{css}</head><body>
<div class="layout">
  <nav class="sidebar"><div class="sidebar-header">
    <div class="sidebar-logo" style="color:#c9a96e">◈ spray</div>
    <div class="sidebar-subtitle" style="font-family:monospace;font-size:12px">credentialed sweep</div>
  </div><div class="sidebar-nav"><div class="nav-section">Navigation</div>{nav}</div></nav>
  <div class="main"><div class="topbar">
    <div class="topbar-title" style="color:#c9a96e">◈ Credentialed Service Sweep</div>
    <div style="display:flex;align-items:center;gap:12px">
      <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">☀ Light</button>
      <span class="topbar-meta">{now.strftime('%Y-%m-%d %H:%M')} · proxenum spray</span>
    </div></div>
    <div class="content">{sections}</div>
  </div></div>{js}
<script>document.addEventListener('DOMContentLoaded',()=>{{const f=document.querySelector('.nav-item');if(f)f.click();}});</script>
</body></html>"""
