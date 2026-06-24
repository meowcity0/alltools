import re
import tempfile
import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from .models import EnumSession
from .runner import Runner

SMB_LINE_RE = re.compile(
    r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+"
    r"\[\*\]\s+(.*?)\s+\(name:(\S+)\)\s+\(domain:(\S+)\)\s+"
    r"\(signing:(\w+)\)\s+\(SMBv1:(\w+)\)"
)


class SMBEnumerator:
    def __init__(self, console: Console, session: EnumSession, no_report: bool = False):
        self.console = console
        self.session = session
        self.no_report = no_report
        self.runner = Runner(console, session)

    def run(self, ips: list[str]):
        self.console.rule("[bold #7aab7a]  SMB Enumeration  ", style="#30363d")

        target, tmp = self._make_target(ips)
        try:
            record = self.runner.run(["nxc", "smb", target], label="SMB Enum")
            self._parse(record.output, ips)
        finally:
            if tmp:
                os.unlink(tmp)

        self._display_results()

    def _make_target(self, ips: list[str]) -> tuple[str, str | None]:
        if len(ips) == 1:
            return ips[0], None
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write("\n".join(ips))
        f.close()
        return f.name, f.name

    def _parse(self, output: str, all_ips: list[str]):
        found = set()
        for line in output.splitlines():
            m = SMB_LINE_RE.search(line)
            if not m:
                continue
            ip, os_info, hostname, domain, signing, smbv1 = m.groups()
            host = self.session.get_or_create_host(ip)
            host.hostname = hostname
            # Only construct an FQDN when domain is a real DNS domain (has a dot
            # or differs from the hostname). When domain == hostname the host is
            # in a workgroup and nxc just echoes back the machine name as domain.
            if domain.lower() != hostname.lower():
                host.fqdn = f"{hostname}.{domain}".lower()
            else:
                host.fqdn = hostname.lower()
            host.domain = domain
            host.os_info = os_info
            host.smb_signing = signing.lower() == "true"
            host.smbv1 = smbv1.lower() == "true"
            found.add(ip)
            # Prefer a real domain (contains a dot) over a bare workgroup name.
            if "." in domain and (self.session.domain == "Unknown" or "." not in self.session.domain):
                self.session.domain = domain
            elif self.session.domain == "Unknown":
                self.session.domain = domain

        for ip in all_ips:
            if "/" not in ip and ip not in found:
                self.session.get_or_create_host(ip)

    def _display_results(self):
        if not self.session.hosts:
            self.console.print("[dim]  No SMB hosts found.[/dim]\n")
            return

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="#30363d",
            header_style="bold #c9a96e",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("IP", style="#c0c8d4")
        table.add_column("Hostname", style="#e6edf3")
        table.add_column("FQDN", style="#8b949e")
        table.add_column("OS", style="#8b949e")
        table.add_column("Domain", style="#7aab7a")
        table.add_column("Signing", justify="center")
        table.add_column("Relay?", justify="center")

        for ip, host in self.session.hosts.items():
            signing = Text("✓", style="green") if host.smb_signing else Text("✗", style="red")
            relay = Text("⚡ YES", style="bold red") if host.relay_candidate else Text("—", style="dim")
            table.add_row(ip, host.hostname, host.fqdn, host.os_info, host.domain, signing, relay)

        self.console.print(table)

        if self.session.domain != "Unknown":
            self.console.print(
                f"\n  [#c9a96e]Domain:[/#c9a96e] [bold #7aab7a]{self.session.domain}[/bold #7aab7a]"
            )

        relay_count = sum(1 for h in self.session.hosts.values() if h.relay_candidate)
        if relay_count:
            self.console.print(
                f"  [bold red]⚡ {relay_count} relay candidate(s) — SMB signing disabled[/bold red]"
            )
        self.console.print()
