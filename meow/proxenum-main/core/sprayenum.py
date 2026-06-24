"""proxenum spray mode — credentialed service sweep.

Purpose: take credentials we already trust (passed on the CLI and/or loaded from
proxenum.json) and hit ONLY the credentialed, easily-missed services
(ssh / ftp / winrm / mssql / mysql / rdp / webdav / smb-shares). It deliberately
does NOT do deep, login-free enumeration (no directory brute force, no vuln
scans) — that's what focus/drill are for.

Ports are reused from proxenum.json when present (so you can omit them); if a
host has no known ports, only the relevant service ports are probed lightly.

Loot is organised per user:  spray/<username>/<service>_<ip>.txt
"""
from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from rich.console import Console

from .models import CommandRecord, CredentialResult, EnumSession
from .adenum import ADCred, _find, _safe_name


# Credentialed services worth a quick authenticated poke, keyed to the ports
# that expose them. (service, {ports}, builds the nxc/tool command)
_SUCCESS_RE = re.compile(r"\[\+\]")
_PWN_RE = re.compile(r"Pwn3d!")


class SprayEnumerator:
    def __init__(
        self,
        console: Console,
        session: EnumSession,
        ips: list[str],
        usernames: list[str] | None = None,
        passwords: list[str] | None = None,
        ntlms: list[str] | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        no_brute: bool = False,
        persist: bool = True,
    ):
        self.console = console
        self.session = session
        self.ips = ips
        self.usernames = list(usernames or [])
        self.passwords = list(passwords or [])
        self.ntlms = list(ntlms or [])
        self.domain = domain or (session.domain if session.domain not in ("Unknown", "") else None)
        self.local_auth = local_auth
        self.no_brute = no_brute
        self.persist = persist
        self.out_root = Path("spray")
        # findings: list of (cred, ip, service, success, is_admin, outfile)
        self.findings: list[tuple] = []

    # ── console helpers ──────────────────────────────────────────────────────
    def _h(self, t): self.console.print(f"\n  [#c9a96e]► {t}[/#c9a96e]")
    def _dim(self, m): self.console.print(f"  [dim #8b949e]  {m}[/dim #8b949e]")
    def _ok(self, m): self.console.print(f"  [bold #7aab7a]  ✓ {m}[/bold #7aab7a]")
    def _warn(self, m): self.console.print(f"  [bold #f85149]  ⚠ {m}[/bold #f85149]")

    def _run(self, cmd: list[str], label: str, timeout: int = 60) -> str:
        self.console.print(f"  [dim #8b949e]  $ {' '.join(map(str, cmd))[:130]}[/dim #8b949e]")
        out, rc = "", -1
        try:
            r = subprocess.run([str(x) for x in cmd], capture_output=True,
                               text=True, timeout=timeout)
            out = (r.stdout or "") + (r.stderr or "")
            rc = r.returncode
        except subprocess.TimeoutExpired:
            out = "(timeout)"
        except FileNotFoundError:
            out = f"(not found: {cmd[0]})"
        except Exception as e:
            out = f"(error: {e})"
        self.session.command_history.append(CommandRecord(
            command=" ".join(map(str, cmd)), output=out[:65536],
            return_code=rc, duration=0.0, label=label, timestamp=datetime.now()))
        return out

    # ── credential set ───────────────────────────────────────────────────────
    def _build_creds(self) -> list[ADCred]:
        creds: list[ADCred] = []
        seen: set = set()

        def _add(user, pw, ntlm, local):
            key = (user, pw or ntlm, local)
            if user and key not in seen:
                seen.add(key)
                creds.append(ADCred(username=user, password=pw, ntlm=ntlm,
                                    domain=self.domain or "", local_auth=local))

        # Explicit -u with -p / -H
        if self.usernames and (self.passwords or self.ntlms):
            if self.no_brute:
                secrets = self.passwords or self.ntlms
                is_ntlm = not self.passwords
                for u, s in zip(self.usernames, secrets):
                    _add(u, "" if is_ntlm else s, s if is_ntlm else "", self.local_auth)
            else:
                for u in self.usernames:
                    for p in self.passwords:
                        _add(u, p, "", self.local_auth)
                    for h in self.ntlms:
                        _add(u, "", h, self.local_auth)

        # Valid creds already proven (from proxenum.json / prior runs)
        for cr in self.session.credentials:
            if cr.success and cr.username:
                _add(cr.username, "" if cr.is_ntlm else cr.password,
                     cr.password if cr.is_ntlm else "", cr.local_auth)
        return creds

    # ── port knowledge ───────────────────────────────────────────────────────
    _SERVICE_PORTS = {21, 22, 139, 445, 1433, 3306, 3389, 5985, 5986, 80, 443, 8080}

    def _ports_for(self, ip: str) -> set[int]:
        host = self.session.hosts.get(ip)
        if host and host.open_ports:
            return set(host.open_ports)
        # Unknown host: light probe of only the credentialed service ports
        if not _find("nmap"):
            return set()
        plist = ",".join(str(p) for p in sorted(self._SERVICE_PORTS))
        lbl = f"spray portcheck {ip}"
        out = self._run(["nmap", "-Pn", "-T4", "--open", f"-p{plist}", "-oG", "-", ip],
                        label=lbl, timeout=120)
        found = set()
        host = self.session.get_or_create_host(ip)
        for m in re.finditer(r"(\d+)/open/tcp//([^/,\s]*)", out):
            p = int(m.group(1)); found.add(p)
            host.open_ports.setdefault(p, m.group(2) or "unknown")
        return found

    # ── per-service enumeration ──────────────────────────────────────────────
    def _user_dir(self, cred: ADCred) -> Path:
        name = cred.username.replace("\\", "/").split("/")[-1]
        safe = re.sub(r"[^A-Za-z0-9._@-]", "_", name).strip("_") or "user"
        d = self.out_root / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _save(self, cred: ADCred, service: str, ip: str, output: str) -> str:
        d = self._user_dir(cred)
        f = d / f"{service}_{_safe_name(ip)}.txt"
        try:
            f.write_text(output, encoding="utf-8")
        except Exception:
            return ""
        return str(f)

    def _nxc(self, proto: str, ip: str, cred: ADCred, extra: list[str]) -> list[str]:
        return ["nxc", proto, ip] + cred.nxc_auth() + extra

    def _probe(self, cred: ADCred, ip: str, service: str, cmd: list[str],
               timeout: int = 60):
        lbl = f"spray {service} {cred.username}@{ip}"
        if any(r.label == lbl for r in self.session.command_history):
            out = next(r.output for r in self.session.command_history if r.label == lbl)
        else:
            out = self._run(cmd, label=lbl, timeout=timeout)
        success = bool(_SUCCESS_RE.search(out))
        is_admin = bool(_PWN_RE.search(out))
        outfile = ""
        if success:
            outfile = self._save(cred, service, ip, out)
            tag = " 👑Pwn3d!" if is_admin else ""
            self._ok(f"{service.upper()} {cred.display()} @ {ip}{tag}")
            # record verified credential
            self.session.credentials.append(CredentialResult(
                username=cred.username, password=cred.ntlm or cred.password, ip=ip,
                protocol=service.upper(), success=True, is_admin=is_admin,
                is_ntlm=cred.is_pth, local_auth=cred.local_auth))
        self.findings.append((cred, ip, service, success, is_admin, outfile))

    def _enum_host(self, cred: ADCred, ip: str, ports: set[int]):
        has_nxc = _find("nxc")
        # SMB shares
        if has_nxc and ports & {139, 445}:
            self._probe(cred, ip, "smb", self._nxc("smb", ip, cred, ["--shares"]))
        # FTP
        if has_nxc and 21 in ports and not cred.is_pth:
            self._probe(cred, ip, "ftp", self._nxc("ftp", ip, cred, []))
        # SSH (run a quick id)
        if has_nxc and 22 in ports and not cred.is_pth:
            self._probe(cred, ip, "ssh", self._nxc("ssh", ip, cred, ["-x", "id"]))
        # WinRM
        if has_nxc and ports & {5985, 5986}:
            self._probe(cred, ip, "winrm", self._nxc("winrm", ip, cred, ["-x", "whoami"]))
        # MSSQL
        if has_nxc and 1433 in ports:
            self._probe(cred, ip, "mssql",
                        self._nxc("mssql", ip, cred, ["-q", "SELECT @@version"]))
        # RDP (auth check only)
        if has_nxc and 3389 in ports:
            self._probe(cred, ip, "rdp", self._nxc("rdp", ip, cred, []))
        # MySQL — nxc has no mysql; use the mysql client
        if 3306 in ports and not cred.is_pth and _find("mysql"):
            mycmd = ["mysql", "-h", ip, "-u", cred.username,
                     "--connect-timeout=10", "-e", "show databases;"]
            if cred.password:
                mycmd.insert(3, f"-p{cred.password}")
            lbl = f"spray mysql {cred.username}@{ip}"
            out = self._run(mycmd, label=lbl, timeout=40)
            if "Database" in out or "information_schema" in out:
                self._ok(f"MYSQL {cred.display()} @ {ip}")
                self.findings.append((cred, ip, "mysql", True, False,
                                      self._save(cred, "mysql", ip, out)))
            else:
                self.findings.append((cred, ip, "mysql", False, False, ""))
        # WebDAV — credentialed davtest against http port(s)
        if not cred.is_pth and (ports & {80, 443, 8080}) and _find("davtest"):
            for wp in sorted(ports & {80, 443, 8080}):
                scheme = "https" if wp == 443 else "http"
                base = f"{scheme}://{ip}" + (f":{wp}" if wp not in (80, 443) else "")
                lbl = f"spray webdav {cred.username}@{ip}:{wp}"
                out = self._run(["davtest", "-url", base, "-auth",
                                 f"{cred.username}:{cred.password}"], label=lbl, timeout=60)
                if "SUCCEED" in out or "PUT" in out:
                    self._ok(f"WEBDAV {cred.display()} @ {base}")
                    self.findings.append((cred, ip, "webdav", True, False,
                                          self._save(cred, "webdav", ip, out)))
                else:
                    self.findings.append((cred, ip, "webdav", False, False, ""))

    # ── main ─────────────────────────────────────────────────────────────────
    def run(self):
        creds = self._build_creds()
        if not creds:
            self._warn("No credentials to spray — supply -u/-p (or run after adenum/scan "
                       "so proxenum.json has valid creds)")
            return
        self._dim(f"{len(creds)} credential(s) · {len(self.ips)} target(s) · "
                  "credentialed services only (no deep enum)")
        for cred in creds:
            self._h(f"Spraying {cred.display()}")
            for ip in self.ips:
                ports = self._ports_for(ip)
                if not ports:
                    self._dim(f"{ip}: no known ports — skipping")
                    continue
                self._enum_host(cred, ip, ports)
        self._persist()
        self._summary()

    def _persist(self):
        if not self.persist:
            return
        try:
            from . import sessiondb
            sessiondb.save(self.session, "2.2.0", full_history=True)
        except Exception:
            pass

    def _summary(self):
        hits = [f for f in self.findings if f[3]]
        self.console.print()
        if hits:
            self._ok(f"{len(hits)} successful credentialed access(es) → spray/<user>/")
        else:
            self._dim("No credentialed services accepted the supplied credentials")
