import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from rich.console import Console
from .models import CommandRecord, EnumSession
from .runner import Runner

_RUSTSCAN_OPEN_RE = re.compile(r"Open\s+\d+\.\d+\.\d+\.\d+:(\d+)")
_RUSTSCAN_GRP_RE  = re.compile(r"\d+\.\d+\.\d+\.\d+\s*->\s*\[([^\]]+)\]")
_NMAP_OG_RE       = re.compile(r"(\d+)/open/tcp//([^/,\s]*)")
_NMAP_NORM_RE     = re.compile(r"^\s*(\d+)/tcp\s+open\s+(\S+)")
_UDP_OG_RE        = re.compile(r"(\d+)/open/udp//([^/,\s]*)")
_UDP_NORM_RE      = re.compile(r"^\s*(\d+)/udp\s+open\s+(\S+)")

# Rejects garbage searchsploit queries from nmap/error output
_BAD_QUERY_RE = re.compile(
    r"/(?:tcp|udp)|^\s*-|\bopen\b|\bfiltered\b|\bport\b|\d+\.\d+\.\d+\.\d+|"
    r"^\d+$|\brc=\d|\berror\b|\bfailed\b|\busage\b",
    re.I,
)


def _find(*names: str) -> str | None:
    for n in names:
        if shutil.which(n):
            return n
    return None


def _wordlist(*paths: str) -> str | None:
    for p in paths:
        if Path(p).exists():
            return p
    return None


def _valid_query(query: str) -> bool:
    """Return False for queries that are clearly nmap/error noise."""
    q = query.strip()
    if len(q) < 3 or len(q) > 60:
        return False
    if not re.search(r"[a-zA-Z]", q):
        return False
    if _BAD_QUERY_RE.search(q):
        return False
    return True


class FocusEnumerator:
    def __init__(self, console: Console, session: EnumSession, ip: str, no_report: bool = False):
        self.console = console
        self.session = session
        self.ip = ip
        self.no_report = no_report
        self.skip_searchsploit: bool = False
        self.runner = Runner(console, session)
        # Where the progressive report is written. Standalone `focus` keeps the
        # historical ./focus.html; `drill` overrides these (per-host directory)
        # so each target lands in its own folder instead of every host
        # clobbering a single ./focus.html.
        self.report_dir: str = "."
        self.report_name: str = "focus.html"
        if not no_report:
            host = session.hosts.get(ip)
            disp = (host.display_name if host and host.display_name != ip
                    else ip.replace(".", "_"))
            self.out_dir: Path | None = Path(disp)
            (self.out_dir / "nmap").mkdir(parents=True, exist_ok=True)
        else:
            self.out_dir = None

    # ── skip helpers ────────────────────────────────────────────────────────

    def _already_done(self, label: str) -> bool:
        """True if command_history has a rc=0 record matching this label."""
        return any(r.label == label and r.return_code == 0
                   for r in self.session.command_history)

    def _get_record(self, label: str) -> "CommandRecord | None":
        """Return last rc=0 record with this label (for reusing saved output)."""
        for r in reversed(self.session.command_history):
            if r.label == label and r.return_code == 0:
                return r
        return None

    def run(self):
        self.console.rule(f"[bold #c9a96e]  ◈ Focus: {self.ip}  ", style="#c9a96e")

        open_ports = self._scan_tcp()
        if not open_ports:
            self.console.print(f"  [dim]  No open TCP ports found on {self.ip}[/dim]")
            return

        self.save_report()  # Phase 1: port scan complete

        port_str = ",".join(str(p) for p in sorted(open_ports))
        self._scan_vuln(port_str)
        self._scan_udp()
        self._enum_snmp()
        self.save_report()  # Phase 2: vuln + UDP + SNMP complete

        self._dispatch(set(open_ports))
        self.save_report()  # Phase 3: all service enum complete

    # ── scanning ───────────────────────────────────────────────────────────

    def _scan_tcp(self) -> list[int]:
        # top-ports fast mode: single nmap -sCV --top-ports N, skip rustscan/-p- entirely
        if self.session.top_ports:
            return self._scan_top_ports_fast()

        # Drill reuse: host already has ports from initial scan — skip discovery
        host = self.session.hosts.get(self.ip)
        if host and host.open_ports:
            existing = sorted(host.open_ports.keys())
            self.console.print(
                f"  [dim #8b949e]  Reusing {len(existing)} TCP ports from initial scan: "
                f"{', '.join(str(p) for p in existing)}[/dim #8b949e]"
            )

            # Skip nmap detail if already completed successfully
            detail_label = f"Nmap detail {self.ip}"
            if self._already_done(detail_label):
                self.console.print(
                    f"  [dim #8b949e]  Nmap detail already complete — skipping[/dim #8b949e]"
                )
                return existing

            oA = ["-oA", str(self.out_dir / "nmap" / "detail")] if self.out_dir else []
            port_str = ",".join(str(p) for p in existing)
            rec = self.runner.run(
                ["sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}"] + oA + [self.ip],
                label=detail_label,
            )
            for line in rec.output.splitlines():
                m = _NMAP_NORM_RE.match(line)
                if m:
                    host.open_ports[int(m.group(1))] = m.group(2)
                for m2 in _NMAP_OG_RE.finditer(line):
                    host.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
            return sorted(host.open_ports.keys())

        # Fresh scan: rustscan + nmap -p- in parallel
        ligolo = self.session.use_ligolo
        ports: set[int] = set()
        rust_out: list[str] = []
        full_out: list[str] = []

        rust_cmd = ["rustscan", "-a", self.ip,
                    "--ulimit", "2000" if ligolo else "5000",
                    "-b",       "500"  if ligolo else "1000"]
        nmap_rate = "500" if ligolo else "1000"
        nmap_timing = "-T3" if ligolo else "-T4"
        full_cmd = ["sudo", "nmap", "-p-", "--min-rate", nmap_rate,
                    nmap_timing, "-Pn", "--open", "-oG", "-", self.ip]

        self.console.print(f"[dim #8b949e]  ❯ {' '.join(rust_cmd)}  (parallel)[/dim #8b949e]")
        self.console.print(f"[dim #8b949e]  ❯ {' '.join(full_cmd)}[/dim #8b949e]")

        def _run_rustscan():
            try:
                r = subprocess.run(rust_cmd, capture_output=True, text=True, timeout=120)
                rust_out.append(r.stdout + r.stderr)
            except Exception as e:
                self.console.print(f"  [dim #8b949e]  rustscan: {e}[/dim #8b949e]")
                rust_out.append("")

        def _run_nmap_full():
            try:
                r = subprocess.run(full_cmd, capture_output=True, text=True, timeout=600)
                full_out.append(r.stdout)
            except Exception as e:
                self.console.print(f"  [dim #8b949e]  nmap -p-: {e}[/dim #8b949e]")
                full_out.append("")

        t0 = time.time()
        t1 = threading.Thread(target=_run_rustscan, daemon=True)
        t2 = threading.Thread(target=_run_nmap_full, daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=130); t2.join(timeout=610)
        elapsed = time.time() - t0

        # Parse rustscan output
        raw_rust = rust_out[0] if rust_out else ""
        for m in _RUSTSCAN_OPEN_RE.finditer(raw_rust):
            ports.add(int(m.group(1)))
        if not ports:
            for m in _RUSTSCAN_GRP_RE.finditer(raw_rust):
                for p in m.group(1).split(","):
                    p = p.strip()
                    if p.isdigit():
                        ports.add(int(p))

        # Parse nmap -p- greppable output
        raw_full = full_out[0] if full_out else ""
        for m in _NMAP_OG_RE.finditer(raw_full):
            ports.add(int(m.group(1)))

        if not ports:
            self.console.print(f"  [dim #8b949e]  No open TCP ports found on {self.ip}[/dim #8b949e]")
            return []

        self.console.print(
            f"  [dim #8b949e]  TCP open ({elapsed:.0f}s): "
            f"{', '.join(str(p) for p in sorted(ports))}[/dim #8b949e]"
        )

        oA = ["-oA", str(self.out_dir / "nmap" / "detail")] if self.out_dir else []
        port_str = ",".join(str(p) for p in sorted(ports))
        detail_extra = (["--max-retries", "2", "--host-timeout", "300s"]
                        if self.session.use_ligolo else [])
        rec = self.runner.run(
            ["sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}"] + detail_extra + oA + [self.ip],
            label=f"Nmap detail {self.ip}",
        )

        host = self.session.get_or_create_host(self.ip)
        for line in rec.output.splitlines():
            m = _NMAP_NORM_RE.match(line)
            if m:
                host.open_ports[int(m.group(1))] = m.group(2)
            for m2 in _NMAP_OG_RE.finditer(line):
                host.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")

        return sorted(ports)

    def _scan_top_ports_fast(self) -> list[int]:
        n = self.session.top_ports
        ligolo = self.session.use_ligolo
        self.console.print(
            f"  [dim #8b949e]  fast mode: top {n} ports only[/dim #8b949e]"
        )
        oA = ["-oA", str(self.out_dir / "nmap" / "detail")] if self.out_dir else []
        extra = (["--max-retries", "2", "--host-timeout", "300s"] if ligolo else
                 ["--max-retries", "1", "--host-timeout", "120s"])
        cmd = ["sudo", "nmap", "-sCV", "-Pn", "--top-ports", str(n)] + extra + oA + [self.ip]
        rec = self.runner.run(cmd, label=f"Nmap top-{n} {self.ip}")
        host = self.session.get_or_create_host(self.ip)
        for line in rec.output.splitlines():
            m = _NMAP_NORM_RE.match(line)
            if m:
                host.open_ports[int(m.group(1))] = m.group(2)
            for m2 in _NMAP_OG_RE.finditer(line):
                host.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
        if host.open_ports:
            self.console.print(
                f"  [dim #8b949e]  open: {', '.join(str(p) for p in sorted(host.open_ports))}[/dim #8b949e]"
            )
        return sorted(host.open_ports.keys())

    def _scan_vuln(self, port_str: str):
        vuln_label = f"Nmap vuln {self.ip}"
        if self._already_done(vuln_label):
            self.console.print(f"\n  [#8b7aa8]► Vulnerability Scan (already complete — skipping)[/#8b7aa8]")
            return
        self.console.print(f"\n  [#8b7aa8]► Vulnerability Scan[/#8b7aa8]")
        oA = ["-oA", str(self.out_dir / "nmap" / "vuln")] if self.out_dir else []
        self.runner.run(
            ["sudo", "nmap", "--script", "vuln", "-Pn", f"-p{port_str}"] + oA + [self.ip],
            label=vuln_label,
        )

    def _scan_udp(self):
        udp_label = f"Nmap UDP {self.ip}"
        if self._already_done(udp_label):
            self.console.print(f"\n  [#8b7aa8]► UDP Scan (already complete — skipping)[/#8b7aa8]")
            # Re-populate udp_ports from saved output
            saved = self._get_record(udp_label)
            if saved:
                host = self.session.get_or_create_host(self.ip)
                for line in saved.output.splitlines():
                    m = _UDP_NORM_RE.match(line)
                    if m:
                        host.udp_ports.setdefault(int(m.group(1)), m.group(2))
                    for m2 in _UDP_OG_RE.finditer(line):
                        host.udp_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
            return
        self.console.print(f"\n  [#8b7aa8]► UDP Scan (top-20)[/#8b7aa8]")
        oA = ["-oA", str(self.out_dir / "nmap" / "udp")] if self.out_dir else []
        rec = self.runner.run(
            ["sudo", "nmap", "-sU", "--top-ports", "20", "-Pn"] + oA + [self.ip],
            label=udp_label,
        )
        host = self.session.get_or_create_host(self.ip)
        for line in rec.output.splitlines():
            m = _UDP_NORM_RE.match(line)
            if m:
                host.udp_ports[int(m.group(1))] = m.group(2)
            for m2 in _UDP_OG_RE.finditer(line):
                host.udp_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")

    # ── per-port dispatch ───────────────────────────────────────────────────

    def _dispatch(self, ports: set[int]):
        host = self.session.hosts.get(self.ip)
        svcs = host.open_ports if host else {}

        def _svc(p: int) -> str:
            return svcs.get(p, "").lower()

        # SMB — standard ports or service name
        if ports & {139, 445} or any(
            t in _svc(p) for p in ports for t in ("microsoft-ds", "netbios-ssn", "/smb")
        ):
            self._enum_smb()

        # HTTP — standard ports OR any port with "http" in service name (covers
        # high ports). Exclude WinRM/WSMan (5985/5986/47001): nmap labels them
        # "http"/"wsman" but they speak SOAP, so dir-busting them is pointless.
        _WINRM_WSMAN = {5985, 5986, 47001}
        http_ports = {
            p for p in ports
            if (p in {80, 443, 8080, 8443, 8000, 8888} or "http" in _svc(p))
            and p not in _WINRM_WSMAN
            and "wsman" not in _svc(p) and "winrm" not in _svc(p)
        }
        for port in sorted(http_ports):
            self._enum_http(port, _svc(port))

        # LDAP
        if ports & {389, 636} or any("ldap" in _svc(p) for p in ports):
            self._enum_ldap()

        # FTP
        if 21 in ports or any("ftp" in _svc(p) for p in ports):
            self._enum_ftp()

        # SSH
        if 22 in ports or any("ssh" in _svc(p) for p in ports):
            self._enum_ssh()

        # MSSQL
        if 1433 in ports or any("mssql" in _svc(p) or "ms-sql" in _svc(p) for p in ports):
            self._enum_mssql()

        # MySQL
        if 3306 in ports or any("mysql" in _svc(p) for p in ports):
            self._enum_mysql()

        # PostgreSQL
        if 5432 in ports or any("postgres" in _svc(p) for p in ports):
            self._enum_postgresql()

        # Redis
        if 6379 in ports or any("redis" in _svc(p) for p in ports):
            self._enum_redis()

        # SMTP
        if 25 in ports or any("smtp" in _svc(p) for p in ports):
            self._enum_smtp()

        # RDP
        if 3389 in ports or any("ms-wbt" in _svc(p) or "rdp" in _svc(p) for p in ports):
            self._enum_rdp()

    # ── handlers ────────────────────────────────────────────────────────────

    def _h(self, title: str):
        self.console.print(f"\n  [#c9a96e]► {title}[/#c9a96e]")

    def _enum_smb(self):
        self._h("SMB (445)")
        for user in ["", "guest"]:
            lbl = f"SMB shares ({user!r}) {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["nxc", "smb", self.ip, "-u", user, "-p", "", "--shares"],
                                label=lbl)
            lbl = f"SMB users ({user!r}) {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["nxc", "smb", self.ip, "-u", user, "-p", "", "--users"],
                                label=lbl)
        if _find("smbclient"):
            lbl = f"smbclient {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["smbclient", "-L", f"//{self.ip}/", "-N"], label=lbl)
        if _find("enum4linux-ng"):
            lbl = f"enum4linux-ng {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["enum4linux-ng", "-A", self.ip], label=lbl)

    def _enum_http(self, port: int, service: str = ""):
        svc = service.lower()
        is_https = port in {443, 8443} or "ssl" in svc or svc == "https"
        scheme = "https" if is_https else "http"
        base = f"{scheme}://{self.ip}" + (f":{port}" if port not in {80, 443} else "")
        self._h(f"HTTP ({port})")

        if _find("whatweb"):
            lbl = f"whatweb {base}"
            if not self._already_done(lbl):
                self.runner.run(["whatweb", base, "-a", "3"], label=lbl)

        lbl = f"curl headers {base}"
        if not self._already_done(lbl):
            self.runner.run(
                ["curl", "-sI", "--connect-timeout", "5", "--max-time", "10", base],
                label=lbl,
            )

        wl = _wordlist(
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt",
            "/usr/share/wordlists/dirb/common.txt",
        )
        if wl and _find("feroxbuster"):
            fb_label = f"feroxbuster {base}"
            fb_rec = self._get_record(fb_label)
            if fb_rec is None:
                fb_cmd = ["feroxbuster", "-u", base, "-w", wl,
                          "--silent", "--no-state", "-t", "50"]
                if not self.session.web_recurse:
                    fb_cmd.append("-n")
                web_exts = self.session.web_exts.strip()
                if web_exts:
                    fb_cmd += ["-x", web_exts]
                if self.session.web_filter_words:
                    fb_cmd += ["--filter-words", str(self.session.web_filter_words)]
                if self.session.web_filter_lines:
                    fb_cmd += ["--filter-lines", str(self.session.web_filter_lines)]
                if self.session.web_filter_size:
                    fb_cmd += ["--filter-size", str(self.session.web_filter_size)]
                fb_rec = self.runner.run(fb_cmd, label=fb_label)

            # Check for .git exposure (uses saved or fresh output)
            if fb_rec and fb_rec.output and ("/.git" in fb_rec.output or "/git" in fb_rec.output.lower()):
                git_dir = None
                if self.out_dir:
                    git_dir = self.out_dir / "git_dump"
                    git_dir.mkdir(exist_ok=True)
                if _find("git-dumper"):
                    lbl = f"git-dumper {base}"
                    if not self._already_done(lbl):
                        self.runner.run(
                            ["git-dumper", f"{base}/.git/", str(git_dir or "/tmp/git_dump")],
                            label=lbl,
                        )
                else:
                    self.console.print(
                        "  [dim #8b949e]  .git found but git-dumper not installed[/dim #8b949e]"
                    )

            # LFI parameter detection
            _LFI_PARAMS = re.compile(
                r'\?(?:.*&)?(?:page|file|path|include|load|view|document|template|'
                r'dir|folder|content|src|url|data|resource|module|action|read)\s*=',
                re.I
            )
            lfi_urls = []
            if fb_rec:
                for line in (fb_rec.output if isinstance(fb_rec.output, str) else "").splitlines():
                    m = re.search(r'https?://\S+', line)
                    if m and _LFI_PARAMS.search(m.group(0)):
                        lfi_urls.append(m.group(0))
            if lfi_urls:
                self.console.print(
                    f"\n  [bold #f85149]⚠ LFI-prone param(s) detected:[/bold #f85149]"
                )
                for u in lfi_urls[:10]:
                    self.console.print(f"    [dim]{u}[/dim]")
                lfi_lbl = f"LFI params {base}"
                if not self._already_done(lfi_lbl):
                    self.session.command_history.append(CommandRecord(
                        command="# LFI parameter detection (feroxbuster output analysis)",
                        output="\n".join(lfi_urls),
                        return_code=0,
                        duration=0.0,
                        label=lfi_lbl,
                    ))

        # davtest: check for WebDAV
        if scheme == "http" and _find("davtest"):
            lbl = f"davtest {base}"
            if not self._already_done(lbl):
                self.runner.run(["davtest", "-url", base], label=lbl)

        # WebDAV auth probe
        if scheme == "http":
            opt_lbl = f"WebDAV OPTIONS {base}"
            opt_rec = self._get_record(opt_lbl)
            if opt_rec is None:
                opt_rec = self.runner.run(
                    ["curl", "-sk", "-X", "OPTIONS", "--connect-timeout", "5", "--max-time", "8",
                     "-D", "-", "-o", "/dev/null", base],
                    label=opt_lbl,
                )
            if opt_rec:
                dav_methods = []
                for line in opt_rec.output.splitlines():
                    if line.lower().startswith("allow:"):
                        for m in ["PROPFIND", "PUT", "MKCOL", "MOVE", "COPY", "DELETE", "LOCK"]:
                            if m in line:
                                dav_methods.append(m)
                if dav_methods:
                    pf_lbl = f"WebDAV PROPFIND (anon) {base}"
                    if not self._already_done(pf_lbl):
                        self.runner.run(
                            ["curl", "-sk", "-X", "PROPFIND", "--connect-timeout", "5",
                             "--max-time", "8", "-D", "-", "-o", "/dev/null", base],
                            label=pf_lbl,
                        )

        # searchsploit: extract versions from whatweb/nmap output and search
        self._run_searchsploit(base)

        # ffuf vhost discovery disabled — produces excessive errors in practice

    def _run_searchsploit(self, context: str = ""):
        """Extract software+version from recent rc=0 command history and run searchsploit."""
        if self.skip_searchsploit:
            return
        if not _find("searchsploit"):
            return

        versions_found: list[tuple[str, str]] = []  # (product, query_string)
        seen_queries: set[str] = set()

        # Only scan outputs from SUCCESSFUL commands (rc=0) to avoid noise from error text
        for rec in self.session.command_history[-20:]:
            if rec.return_code != 0:
                continue
            out = rec.output

            # whatweb: parse "ProductName[version]" patterns
            for m in re.finditer(r"(\w[\w\s\-\.]+)\[([^\]]{2,30})\]", out):
                product, ver = m.group(1).strip(), m.group(2).strip()
                if re.match(r"^\d|^https?|^ZZ$|^\d{3}$", product):
                    continue
                if re.search(r"[@\|\[\]]", ver):
                    continue
                ver_short = re.sub(r"^(\d+\.\d+).*", r"\1", ver) if re.match(r"\d", ver) else ver
                query = f"{product} {ver_short}"
                if query not in seen_queries and _valid_query(query):
                    seen_queries.add(query)
                    versions_found.append((product, query))

            # nmap: parse "service/version" from port lines
            for m in re.finditer(r"\d+/tcp\s+open\s+(\S+)\s+([^\r\n]{4,40})", out):
                svc, detail = m.group(1), m.group(2).strip()
                parts = detail.split()
                if len(parts) >= 2:
                    query = " ".join(parts[:2])
                    if query not in seen_queries and _valid_query(query):
                        seen_queries.add(query)
                        versions_found.append((svc, query))

            # nmap SSL cert commonName — short bare product names only
            for m in re.finditer(r"commonName=([^\s,/\|]+)", out):
                cn = m.group(1).strip()
                if re.match(r"^\d+\.\d+", cn) or cn.startswith("*") or len(cn) > 30:
                    continue
                if cn.count(".") >= 2:
                    continue
                if cn not in seen_queries and _valid_query(cn):
                    seen_queries.add(cn)
                    versions_found.append((cn, cn))

            # nmap SAN: DNS:<name>
            for m in re.finditer(r"DNS:([a-zA-Z][^\s,\|]{1,28})", out):
                dns = m.group(1).strip()
                if dns.count(".") >= 2 or len(dns) < 3:
                    continue
                if dns not in seen_queries and _valid_query(dns):
                    seen_queries.add(dns)
                    versions_found.append((dns, dns))

        if not versions_found:
            return

        _SKIP_WORDS = {"OK", "HTTP", "Apache", "nginx", "OpenSSH", "Microsoft", "ISS", "Ubuntu"}
        _OSCP_PRIORITY = re.compile(
            r"(?i)(remote\s*code\s*exec|rce|\brce\b|command\s*inject|file\s*inclusion"
            r"|sql\s*inject|privilege\s*escal|local\s*file|path\s*trav|deseria)",
            re.I,
        )
        _SKIP_TYPES = re.compile(r"(?i)(dos|denial.of.service|xss|csrf|cross.site|phish|spam)", re.I)

        self._h("Searchsploit (version scan)")
        for product, query in versions_found[:8]:
            if any(w.lower() == product.lower() for w in _SKIP_WORDS):
                continue
            lbl = f"searchsploit [{query}]"
            if self._already_done(lbl):
                # Print hits from saved output
                saved = self._get_record(lbl)
                if saved:
                    self._print_sploit_hits(saved.output, query, _OSCP_PRIORITY, _SKIP_TYPES)
                continue
            rec = self.runner.run(["searchsploit", query], label=lbl)
            self._print_sploit_hits(rec.output, query, _OSCP_PRIORITY, _SKIP_TYPES)

    def _print_sploit_hits(self, output: str, query: str, oscp_re, skip_re):
        lines = output.splitlines()
        hits = []
        for line in lines:
            if "|" not in line or "Path" in line or "---" in line:
                continue
            if skip_re.search(line):
                continue
            priority = "🔴" if oscp_re.search(line) else "  "
            hits.append(f"{priority} {line.strip()}")
        if hits:
            self.console.print(f"  [dim #8b949e]  searchsploit [{query}][/dim #8b949e]")
            for h in hits[:8]:
                self.console.print(f"    [dim]{h}[/dim]")

    def save_report(self):
        """Generate a partial report to disk (called after each major phase)."""
        if self.no_report:
            return
        try:
            from .report import FocusReport
            out = FocusReport(self.console, self.session, self.ip).generate(
                output_dir=self.report_dir, filename=self.report_name, quiet=True)
            self.console.print(
                f"  [dim #656d76]  📄 Report updated: {out}[/dim #656d76]"
            )
        except Exception as e:
            # Surface failures instead of silently losing the report.
            self.console.print(
                f"  [bold #f85149]  ⚠ report write failed ({self.report_dir}/"
                f"{self.report_name}): {e}[/bold #f85149]"
            )

    def _enum_ldap(self):
        self._h("LDAP (389/636)")
        for user in ["", "guest"]:
            lbl = f"LDAP anon ({user!r}) {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["nxc", "ldap", self.ip, "-u", user, "-p", "", "--users"],
                                label=lbl)
        domain = self.session.domain
        if domain != "Unknown" and "." in domain and _find("ldapsearch"):
            dn = ",".join(f"DC={p}" for p in domain.split("."))
            lbl = f"ldapsearch {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(
                    ["ldapsearch", "-H", f"ldap://{self.ip}", "-x",
                     "-b", dn, "-s", "sub",
                     "(&(objectClass=user)(objectCategory=person))",
                     "sAMAccountName", "description", "memberOf"],
                    label=lbl,
                )

    def _enum_ftp(self):
        self._h("FTP (21)")
        lbl = f"FTP anon {self.ip}"
        if not self._already_done(lbl):
            self.runner.run(["nxc", "ftp", self.ip, "-u", "anonymous", "-p", "anonymous"],
                            label=lbl)

    def _enum_ssh(self):
        self._h("SSH (22)")
        lbl = f"SSH banner {self.ip}"
        if not self._already_done(lbl):
            self.runner.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", self.ip, "exit"],
                label=lbl,
            )

    def _enum_mssql(self):
        self._h("MSSQL (1433)")
        lbl = f"MSSQL info {self.ip}"
        if not self._already_done(lbl):
            self.runner.run(["nxc", "mssql", self.ip], label=lbl)
        for u, p in [("sa", ""), ("sa", "sa")]:
            lbl = f"MSSQL {u} {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["nxc", "mssql", self.ip, "-u", u, "-p", p], label=lbl)

    def _enum_mysql(self):
        self._h("MySQL (3306)")
        for u in ["root", ""]:
            lbl = f"MySQL '{u}' {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(
                    ["mysql", "-h", self.ip, "-u", u, "--password=",
                     "--connect-timeout", "5", "-e", "SHOW DATABASES;"],
                    label=lbl,
                )

    def _enum_postgresql(self):
        self._h("PostgreSQL (5432)")
        for u in ["postgres", "admin"]:
            lbl = f"PostgreSQL {u} {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(
                    ["bash", "-c",
                     f"PGPASSWORD='' psql -h {self.ip} -U {u} "
                     f"--connect-timeout 5 -c '\\l' 2>&1"],
                    label=lbl,
                )

    def _enum_redis(self):
        self._h("Redis (6379)")
        if _find("redis-cli"):
            lbl = f"Redis ping {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["redis-cli", "-h", self.ip, "ping"], label=lbl)
            lbl = f"Redis info {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["redis-cli", "-h", self.ip, "info"], label=lbl)

    def _enum_smtp(self):
        self._h("SMTP (25)")
        if _find("nxc"):
            lbl = f"SMTP {self.ip}"
            if not self._already_done(lbl):
                self.runner.run(["nxc", "smtp", self.ip], label=lbl)

    def _enum_snmp(self):
        host = self.session.hosts.get(self.ip)
        if not host or 161 not in host.udp_ports:
            return
        self._h("SNMP (udp/161)")
        community = "public"
        out_dir = self.out_dir

        snmp_lbl = f"snmp-check {self.ip}"
        snmp_rec = self._get_record(snmp_lbl)
        if snmp_rec is None:
            snmp_out_file = str(out_dir / "snmp-check.txt") if out_dir else None
            snmp_rec = self.runner.run(
                ["snmp-check", self.ip, "-c", community],
                label=snmp_lbl,
            )
            if (snmp_rec.output.strip() and "Timeout" not in snmp_rec.output
                    and len(snmp_rec.output) > 100 and snmp_out_file):
                Path(snmp_out_file).write_text(snmp_rec.output, encoding="utf-8")
                self.console.print(f"  [dim #8b949e]  SNMP data → {snmp_out_file}[/dim #8b949e]")

        if (snmp_rec and snmp_rec.return_code == 0 and snmp_rec.output.strip()
                and "Timeout" not in snmp_rec.output and len(snmp_rec.output) > 100):
            self._run_snmpbulkwalk(community, out_dir)
            self._run_searchsploit_snmp(snmp_rec.output)
            return

        # Fallback: onesixtyone to brute-force community string, then retry
        found_community = self._discover_snmp_community()
        if found_community:
            community = found_community
            snmp_lbl2 = f"snmp-check {self.ip} ({community})"
            snmp_rec2 = self._get_record(snmp_lbl2)
            if snmp_rec2 is None:
                snmp_out_file2 = str(out_dir / "snmp-check.txt") if out_dir else None
                snmp_rec2 = self.runner.run(
                    ["snmp-check", self.ip, "-c", community],
                    label=snmp_lbl2,
                )
                if snmp_rec2 and len(snmp_rec2.output) > 100 and snmp_out_file2:
                    Path(snmp_out_file2).write_text(snmp_rec2.output, encoding="utf-8")
            if snmp_rec2 and len(snmp_rec2.output) > 100:
                self._run_snmpbulkwalk(community, out_dir)
                self._run_searchsploit_snmp(snmp_rec2.output)

    def _discover_snmp_community(self) -> "str | None":
        """Use onesixtyone to brute-force community string. Returns found string or None."""
        if not _find("onesixtyone"):
            return None
        wordlist = _wordlist(
            "/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt",
            "/usr/share/doc/onesixtyone/dict.txt",
            "/usr/share/onesixtyone/dict.txt",
        )
        lbl = f"onesixtyone {self.ip}"
        if not self._already_done(lbl):
            cmd = (["onesixtyone", "-c", wordlist, self.ip] if wordlist
                   else ["onesixtyone", self.ip, "public"])
            rec = self.runner.run(cmd, label=lbl)
        else:
            rec = self._get_record(lbl)
        if rec and rec.output.strip():
            m = re.search(r"\[(\w+)\]", rec.output)
            if m:
                return m.group(1)
        return None

    def _run_snmpbulkwalk(self, community: str, out_dir):
        """Run snmpbulkwalk for 4 key OIDs and save combined output to snmpbulkwalk.txt."""
        if not _find("snmpbulkwalk"):
            return
        oids = [
            (".1.3.6.1.4.1.8072.1.3.2.3", "custom-script-output"),
            (".1.3.6.1.4.1.8072.1.3.2.2", "custom-script-cmds"),
            (".1.3.6.1.2.1.25.4.2.1",     "processes"),
            (".1.3.6.1.2.1.25.6.3.1",     "software"),
        ]
        all_parts = []
        for oid, name in oids:
            lbl = f"snmpbulkwalk {name} {self.ip}"
            rec = self._get_record(lbl)
            if rec is None:
                rec = self.runner.run(
                    ["snmpbulkwalk", "-v", "2c", "-c", community,
                     "-Cn0", "-Cr50", self.ip, oid],
                    label=lbl,
                )
            if rec and rec.output.strip():
                all_parts.append(f"### {name} ({oid}) ###\n{rec.output}")
        if all_parts and out_dir:
            out_file = out_dir / "snmpbulkwalk.txt"
            out_file.write_text("\n\n".join(all_parts), encoding="utf-8")
            self.console.print(f"  [dim #8b949e]  snmpbulkwalk → {out_file}[/dim #8b949e]")

    def _run_searchsploit_snmp(self, snmp_output: str):
        """Extract software/service names from snmp-check output and run searchsploit."""
        if self.skip_searchsploit:
            return
        if not _find("searchsploit"):
            return

        queries: list[str] = []
        seen: set[str] = set()

        _SKIP_VENDORS = re.compile(
            r"^(Microsoft|VMware|Windows|Update for|KB\d|Visual C\+\+|"
            r"\.NET|Edge|WebView|Redistributable|DCOM|Remote Desktop|"
            r"WAN Miniport|svchost|lsass|csrss|wininit|services|winlogon|"
            r"dwm|fontdrvhost|spoolsv|msdtc|SearchIndexer|RuntimeBroker|"
            r"sihost|taskhostw|ctfmon|explorer|smss|MsMpEng|SgrmBroker|"
            r"Memory Compression|Registry|System Idle|System$|PuTTY$)",
            re.I,
        )
        _WIN_PROCS = {
            "svchost", "lsass", "csrss", "wininit", "services", "winlogon",
            "dwm", "fontdrvhost", "spoolsv", "msdtc", "searchindexer",
            "runtimebroker", "sihost", "taskhostw", "ctfmon", "explorer",
            "smss", "msmpeng", "sgrmbroker", "w3wp", "dllhost", "wmiPrvSE",
            "system", "registry", "memory compression", "system idle process",
            "vmtoolsd", "vm3dservice", "vgauthservice", "moUsoCoreWorker",
        }
        _OSCP_PRIORITY = re.compile(
            r"(?i)(remote\s*code\s*exec|rce|\brce\b|command\s*inject|file\s*inclusion"
            r"|sql\s*inject|privilege\s*escal|local\s*file|path\s*trav|deseria)",
            re.I,
        )
        _SKIP_TYPES = re.compile(
            r"(?i)(dos|denial.of.service|xss|csrf|cross.site|phish|spam)", re.I
        )

        def _add(q: str):
            q = q.strip()
            if q and q not in seen and len(q) >= 4 and len(q) < 55:
                seen.add(q)
                queries.append(q)

        # ── 1. [*] Software components section ──────────────────────────────
        in_software = False
        for line in snmp_output.splitlines():
            if "[*] Software components" in line:
                in_software = True
                continue
            if line.startswith("[*]") and "Software" not in line:
                in_software = False
                continue
            if not in_software:
                continue
            m = re.match(r"\s+\d+\s+(.+)", line)
            if not m:
                continue
            name = m.group(1).strip()
            if _SKIP_VENDORS.match(name):
                continue
            ver_m = re.search(r"v?(\d+[\d\.]{2,})", name)
            if ver_m:
                ver = ver_m.group(1).rstrip(".")
                prod = re.sub(r"\s*(version|release|v)\s*[\d\.]+.*$", "", name, flags=re.I)
                prod = re.sub(r"\s*\(.*?\)$", "", prod).strip()
                if prod and len(prod) >= 3:
                    _add(f"{prod} {ver}")
                    _add(prod)
            else:
                if len(name.split()) <= 4 and not _SKIP_VENDORS.match(name):
                    _add(name)

        # ── 2. [*] Processes section ─────────────────────────────────────────
        in_procs = False
        for line in snmp_output.splitlines():
            if "[*] Processes" in line:
                in_procs = True
                continue
            if line.startswith("[*]") and "Process" not in line:
                in_procs = False
                continue
            if not in_procs:
                continue
            m = re.match(r"\s+\d+\s+\w+\s+(\S+\.exe)\s*(.*)", line, re.I)
            if not m:
                continue
            exe, path_args = m.group(1), m.group(2)
            exe_base = re.sub(r"\.exe$", "", exe, flags=re.I).strip()
            if exe_base.lower() in _WIN_PROCS:
                continue
            ver_from_path = re.search(r"\\([\d]+\.[\d\.]+)\\", path_args)
            if ver_from_path:
                _add(f"{exe_base} {ver_from_path.group(1)}")
            else:
                readable = re.sub(r"([a-z])([A-Z])", r"\1 \2", exe_base)
                if readable.lower() not in _WIN_PROCS:
                    _add(readable)

        # ── 3. Fallback: generic version-string scan ─────────────────────────
        if not queries:
            for m in re.finditer(r"(\w[\w\s\-\.]{3,25}?)\s+v?(\d+\.\d+[\.\d]*)", snmp_output):
                prod = m.group(1).strip()
                ver = re.sub(r"^(\d+\.\d+).*", r"\1", m.group(2))
                if not _SKIP_VENDORS.match(prod):
                    _add(f"{prod} {ver}")

        if not queries:
            return

        self._h("Searchsploit (SNMP)")
        for query in queries[:6]:
            lbl = f"searchsploit (SNMP) [{query}]"
            if self._already_done(lbl):
                saved = self._get_record(lbl)
                if saved:
                    self._print_sploit_hits(saved.output, query, _OSCP_PRIORITY, _SKIP_TYPES)
                continue
            rec = self.runner.run(["searchsploit", query], label=lbl)
            self._print_sploit_hits(rec.output, query, _OSCP_PRIORITY, _SKIP_TYPES)

    def _enum_rdp(self):
        self._h("RDP (3389)")
        lbl = f"RDP banner {self.ip}"
        if not self._already_done(lbl):
            self.runner.run(["nxc", "rdp", self.ip], label=lbl)
