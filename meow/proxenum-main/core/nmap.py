import re
import shutil
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from .models import EnumSession
from .runner import Runner

RUSTSCAN_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s*->\s*\[([^\]]+)\]")
RUSTSCAN_OPEN_RE = re.compile(r"Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)")
NMAP_OG_PORT_RE = re.compile(r"(\d+)/open/tcp//([^/,\s]*)")


def _safe_dir_name(s: str) -> str:
    return s.replace(".", "_").replace(" ", "_")


class NmapScanner:
    def __init__(self, console: Console, session: EnumSession, no_report: bool = False):
        self.console = console
        self.session = session
        self.no_report = no_report
        self.runner = Runner(console, session)

    def run(self, ips: list[str]):
        self.console.rule("[bold #7aab7a]  Nmap Scanning  ", style="#30363d")

        targets = [ip for ip in self.session.hosts if "/" not in ip]
        if not targets:
            targets = [ip for ip in ips if "/" not in ip]

        for ip in targets:
            self.console.print(f"\n  [#c9a96e]► {ip}[/#c9a96e]")
            if self.session.use_proxy:
                self._scan_proxy(ip)
            elif self.session.use_ligolo:
                self._scan_ligolo(ip)
            else:
                self._scan_direct(ip)

        self._display_results()

    # ---------------------------------------------------------------- top-ports fast mode
    # Single nmap -sCV --top-ports N — skips rustscan + nmap -p- pipeline entirely.
    # Use when speed matters more than full coverage.

    def _scan_top_ports(self, ip: str, host, ligolo: bool = False):
        n = self.session.top_ports
        host_dir = self._host_dir(ip, host.display_name)
        detail_base = str(host_dir / "nmap" / "detail") if host_dir else None
        extra = (["--max-retries", "2", "--host-timeout", "300s"] if ligolo else
                 ["--max-retries", "1", "--host-timeout", "120s"])
        cmd = ["sudo", "nmap", "-sCV", "-Pn", f"--top-ports", str(n)] + extra + [ip]
        if detail_base:
            cmd += ["-oA", detail_base]
        self.console.print(
            f"  [dim #8b949e]  fast mode: top {n} ports[/dim #8b949e]"
        )
        rec = self.runner.run(cmd, label=f"Nmap top-{n} {ip}")
        for port, svc in self._parse_nmap_og(rec.output).items():
            host.open_ports[port] = svc
        # Also parse normal format
        for line in rec.output.splitlines():
            m2 = __import__("re").match(r"^\s*(\d+)/tcp\s+open\s+(\S+)", line)
            if m2:
                host.open_ports[int(m2.group(1))] = m2.group(2)
        if host_dir and detail_base:
            xml_path = Path(detail_base + ".xml")
            html_path = host_dir / "detail.html"
            xsl = Path("/usr/share/nmap/nmap.xsl")
            if xml_path.exists() and xsl.exists() and shutil.which("xsltproc"):
                subprocess.run(
                    ["xsltproc", "-o", str(html_path), str(xsl), str(xml_path)],
                    capture_output=True,
                )
                self.console.print(
                    f"  [dim #8b949e]  HTML report → {html_path}[/dim #8b949e]"
                )

    # ---------------------------------------------------------------- proxy mode
    # TCP-connect scan (-sT), no sudo, proxy-safe timing, top-30 ports only.
    # These flags are specifically chosen to work through a SOCKS proxy:
    # -sT  → TCP connect (not SYN); proxychains can relay full TCP connections
    # -Pn  → skip ping (ICMP won't traverse the proxy)
    # -T4  → moderate timing; aggressive but not reckless over a tunnel
    # --top-ports 30   → keep the scan short; full scans are impractical over a tunnel
    # --max-retries 1  → don't hammer a slow proxy with retries
    # --host-timeout 90s → abort hung hosts quickly
    # -oG -  → greppable output to stdout so we don't need a temp file

    def _scan_proxy(self, ip: str):
        host = self.session.get_or_create_host(ip)
        cmd = [
            "nmap", "-sT", "-Pn", "-T4",
            "--top-ports", "30",
            "--max-retries", "1",
            "--host-timeout", "90s",
            "-oG", "-", ip,
        ]
        record = self.runner.run(cmd, label=f"Nmap {ip}")
        for port, svc in self._parse_nmap_og(record.output).items():
            host.open_ports[port] = svc

    # ---------------------------------------------------------------- direct mode
    # Full pipeline: rustscan → parallel sudo nmap -sCV + sudo nmap -p- → xsltproc.
    # sudo is required for SYN scan (-sS, the default when root); -sCV also runs
    # version/script detection which needs raw socket access.
    # This pipeline must NEVER run through proxychains — rustscan uses async UDP/TCP
    # that breaks over SOCKS, and full-range scans over a proxy are unusable.

    def _scan_direct(self, ip: str):
        host = self.session.get_or_create_host(ip)
        if self.session.top_ports:
            self._scan_top_ports(ip, host)
            return

        # 1. rustscan — fast async discovery (never proxied)
        rust_ports = set(self._rustscan(ip))

        # 2. nmap -p- — full-range confirmation (sequential, wait before -sCV)
        host_dir = self._host_dir(ip, host.display_name)
        full_base = str(host_dir / "nmap" / "full") if host_dir else None
        full_cmd = ["sudo", "nmap", "-p-", "--min-rate", "1000", "-Pn", ip]
        if full_base:
            full_cmd += ["-oA", full_base]
        rec_full = self.runner.run(full_cmd, label=f"Nmap full {ip}")
        full_ports = set(self._parse_nmap_og(rec_full.output).keys())

        # 3. Merge — confirmed open ports from both tools
        all_ports = sorted(rust_ports | full_ports)
        if not all_ports:
            self.console.print(f"  [dim]  No open ports found on {ip}[/dim]")
            return

        port_str = ",".join(str(p) for p in all_ports)
        self.console.print(
            f"  [dim #8b949e]  confirmed open ({len(all_ports)}): {port_str}[/dim #8b949e]"
        )

        # 4. ONE nmap -sCV on all confirmed ports — single detail file, no detail_extra
        detail_base = str(host_dir / "nmap" / "detail") if host_dir else None
        detail_cmd = ["sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}", ip]
        if detail_base:
            detail_cmd += ["-oA", detail_base]
        rec_detail = self.runner.run(detail_cmd, label=f"Nmap detail {ip}")

        # 5. Store parsed services
        detail_ports = self._parse_nmap_og(rec_detail.output)
        for port, svc in detail_ports.items():
            host.open_ports[port] = svc
        if not detail_ports:
            for p in all_ports:
                host.open_ports.setdefault(p, "unknown")

        # 6. xsltproc: detail.xml → detail.html (single file, always)
        if host_dir and detail_base:
            xml_path = Path(detail_base + ".xml")
            html_path = host_dir / "detail.html"
            xsl = Path("/usr/share/nmap/nmap.xsl")
            if xml_path.exists() and xsl.exists() and shutil.which("xsltproc"):
                subprocess.run(
                    ["xsltproc", "-o", str(html_path), str(xsl), str(xml_path)],
                    capture_output=True,
                )
                self.console.print(
                    f"  [dim #8b949e]  HTML report → {html_path}[/dim #8b949e]"
                )

    # ---------------------------------------------------------------- ligolo mode
    # ligolo-ng creates a real TUN interface: SYN scans work, no proxychains needed.
    # Tunnel latency requires conservative timing to avoid dropped packets.

    def _scan_ligolo(self, ip: str):
        host = self.session.get_or_create_host(ip)
        if self.session.top_ports:
            self._scan_top_ports(ip, host, ligolo=True)
            return

        # 1. rustscan — lower ulimit/batch to reduce tunnel congestion
        rust_ports = set(self._rustscan(ip, ulimit=2000, batch=500))

        # 2. nmap -p- — conservative rate for tunnel
        host_dir = self._host_dir(ip, host.display_name)
        full_base = str(host_dir / "nmap" / "full") if host_dir else None
        full_cmd = ["sudo", "nmap", "-p-", "--min-rate", "500", "-T3", "-Pn", ip]
        if full_base:
            full_cmd += ["-oA", full_base]
        rec_full = self.runner.run(full_cmd, label=f"Nmap full (ligolo) {ip}")
        full_ports = set(self._parse_nmap_og(rec_full.output).keys())

        # 3. Merge confirmed ports
        all_ports = sorted(rust_ports | full_ports)
        if not all_ports:
            self.console.print(f"  [dim]  No open ports found on {ip}[/dim]")
            return

        port_str = ",".join(str(p) for p in all_ports)
        self.console.print(
            f"  [dim #8b949e]  confirmed open ({len(all_ports)}): {port_str}[/dim #8b949e]"
        )

        # 4. ONE nmap -sCV — add retries and host-timeout for tunnel stability
        detail_base = str(host_dir / "nmap" / "detail") if host_dir else None
        detail_cmd = [
            "sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}",
            "--max-retries", "2", "--host-timeout", "300s", ip,
        ]
        if detail_base:
            detail_cmd += ["-oA", detail_base]
        rec_detail = self.runner.run(detail_cmd, label=f"Nmap detail (ligolo) {ip}")

        detail_ports = self._parse_nmap_og(rec_detail.output)
        for port, svc in detail_ports.items():
            host.open_ports[port] = svc
        if not detail_ports:
            for p in all_ports:
                host.open_ports.setdefault(p, "unknown")

        # 5. xsltproc → detail.html
        if host_dir and detail_base:
            xml_path = Path(detail_base + ".xml")
            html_path = host_dir / "detail.html"
            xsl = Path("/usr/share/nmap/nmap.xsl")
            if xml_path.exists() and xsl.exists() and shutil.which("xsltproc"):
                subprocess.run(
                    ["xsltproc", "-o", str(html_path), str(xsl), str(xml_path)],
                    capture_output=True,
                )
                self.console.print(
                    f"  [dim #8b949e]  HTML report → {html_path}[/dim #8b949e]"
                )

    # ---------------------------------------------------------------- helpers

    def _rustscan(self, ip: str, ulimit: int = 5000, batch: int = 1000) -> list[int]:
        """Run rustscan directly (never through proxychains)."""
        cmd = ["rustscan", "-a", ip, "--ulimit", str(ulimit), "-b", str(batch)]
        self.console.print(f"[dim #8b949e]  ❯ {' '.join(cmd)}[/dim #8b949e]")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.console.print(f"  [dim #8b949e]  rustscan error: {e}[/dim #8b949e]")
            return []
        output = result.stdout + result.stderr

        ports: list[int] = []
        # "IP -> [80,443,22]" (greppable format)
        for m in RUSTSCAN_RE.finditer(output):
            for p in m.group(2).split(","):
                p = p.strip()
                if p.isdigit():
                    ports.append(int(p))
        # "Open IP:PORT" (default format)
        if not ports:
            for m in RUSTSCAN_OPEN_RE.finditer(output):
                ports.append(int(m.group(2)))

        if not ports and output.strip():
            snippet = output.strip().splitlines()[0][:120]
            self.console.print(f"  [dim #8b949e]  rustscan raw: {snippet}[/dim #8b949e]")

        return sorted(set(ports))

    def _nmap_discover(self, ip: str) -> list[int]:
        """TCP connect full-port discovery via nmap (fallback, no sudo needed)."""
        cmd = [
            "nmap", "-sT", "-Pn", "-T4",
            "--top-ports", "1000",
            "--open", "-oG", "-", ip,
        ]
        self.console.print(f"[dim #8b949e]  ❯ {' '.join(cmd)}[/dim #8b949e]")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            return []
        return list(self._parse_nmap_og(result.stdout).keys())

    def _parse_nmap_og(self, output: str) -> dict[int, str]:
        ports: dict[int, str] = {}
        for line in output.splitlines():
            for m in NMAP_OG_PORT_RE.finditer(line):
                ports[int(m.group(1))] = m.group(2) or "unknown"
            m2 = re.match(r"^\s*(\d+)/tcp\s+open\s+(\S+)", line)
            if m2:
                ports[int(m2.group(1))] = m2.group(2)
        return ports

    def _host_dir(self, ip: str, display_name: str) -> Path | None:
        if self.no_report:
            return None
        name = display_name if display_name != ip else _safe_dir_name(ip)
        d = Path(name) / "nmap"
        d.mkdir(parents=True, exist_ok=True)
        return d.parent

    # ---------------------------------------------------------------- display

    def _display_results(self):
        has_ports = any(h.open_ports for h in self.session.hosts.values())
        if not has_ports:
            self.console.print("[dim]  No open ports found.[/dim]\n")
            return

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="#30363d",
            header_style="bold #c9a96e",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Host", style="#c0c8d4")
        table.add_column("IP", style="#8b949e")
        table.add_column("Open Ports", style="#7aab7a")

        for ip, host in self.session.hosts.items():
            if not host.open_ports:
                continue
            ports = "  ".join(
                f"[#7aab7a]{p}[/#7aab7a][dim #8b949e]/{s}[/dim #8b949e]"
                for p, s in sorted(host.open_ports.items())
            )
            table.add_row(host.display_name, ip, ports)

        self.console.print(table)
        self.console.print()
