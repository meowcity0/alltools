import re
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
_SAM_LINE_RE = re.compile(
    r"([^\s:]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::", re.I
)
# Cached domain logon hash — "domain/username:$DCC2$..." or "domain\username:$DCC1$..."
_DCC_LINE_RE = re.compile(r"[\\/]([^\s:\\/]+):\$DCC[12]?\$")
# DefaultPassword line — "(Unknown User):password" or "domain\username:password"
_DEFAULT_PW_RE = re.compile(r"^(\(Unknown User\)|[^\s:]+):(.+)$")
# nxc-style line prefix — "SMB   <ip> <port>   <hostname>   <rest>"
_PROTO_PREFIX_RE = re.compile(
    r"^(?:SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI|HTTP)\s+\S+\s+\d+\s+\S+\s+(.*)$"
)


class StaticAnalyzer:
    def __init__(self, console: Console):
        self.console = console

    def crack_ntlm(self, hash_file: str, user_map: dict[str, str] | None = None) -> dict[str, str]:
        self.console.rule("[bold #7aab7a]  NTLM Hash Cracking  ", style="#30363d")
        path = Path(hash_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {hash_file}[/red]\n")
            return {}

        cmd = [
            "hashcat", "-m", "1000", "-a", "0",
            str(path), "/usr/share/wordlists/rockyou.txt",
            "--potfile-disable", "--quiet",
        ]
        self.console.print(f"[dim #8b949e]  ❯ {' '.join(cmd)}[/dim #8b949e]")
        self.console.print("[dim]  Running hashcat... (this may take a while)[/dim]")

        result = subprocess.run(cmd, capture_output=True, text=True)

        cracked: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    cracked[parts[0].lower()] = parts[-1]

        if not cracked:
            self.console.print("[dim]  No hashes cracked.[/dim]\n")
            return {}

        self.console.print(f"\n  [bold #7aab7a]✓ {len(cracked)} hash(es) cracked![/bold #7aab7a]\n")

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="#30363d",
            header_style="bold #c9a96e",
            show_edge=False,
            padding=(0, 1),
        )
        show_user = user_map is not None
        if show_user:
            table.add_column("Username", style="bold #e6edf3")
        table.add_column("Hash", style="#8b949e")
        table.add_column("Password", style="bold #7aab7a")
        for h, pw in cracked.items():
            row = []
            if show_user:
                row.append(user_map.get(h, "—"))
            row += [h[:32], pw]
            table.add_row(*row)

        self.console.print(table)
        self.console.print()
        return cracked

    # ────────────────────────────────────────────── merge / pull

    def merge_files(self, files: list[str], output: str):
        """Merge multiple word/hash files into one, deduplicating."""
        self.console.rule("[bold #7aab7a]  File Merge  ", style="#30363d")
        out_path = Path(output)
        entries: list[str] = []
        seen: set[str] = set()
        for f in files:
            p = Path(f)
            if not p.exists():
                self.console.print(f"  [red]Not found: {f}[/red]")
                continue
            added = 0
            for line in p.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and line not in seen:
                    entries.append(line)
                    seen.add(line)
                    added += 1
            self.console.print(f"  [dim #8b949e]  {f} → {added} entries[/dim #8b949e]")
        out_path.write_text("\n".join(entries) + ("\n" if entries else ""), encoding="utf-8")
        self.console.print(
            f"\n  [bold #7aab7a]✓ {len(entries)} unique entries → {output}[/bold #7aab7a]\n"
        )

    def push_file(self, source: str, target: str):
        """Update target with new entries from source (dedup in place)."""
        self.console.rule("[bold #7aab7a]  File Push (update)  ", style="#30363d")
        src, tgt = Path(source), Path(target)
        if not src.exists():
            self.console.print(f"  [red]Source not found: {source}[/red]\n")
            return
        seen: set[str] = set()
        existing: list[str] = []
        if tgt.exists():
            for line in tgt.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and line not in seen:
                    existing.append(line)
                    seen.add(line)
        new: list[str] = []
        for line in src.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and line not in seen:
                new.append(line)
                seen.add(line)
        all_entries = existing + new
        tgt.write_text("\n".join(all_entries) + ("\n" if all_entries else ""), encoding="utf-8")
        self.console.print(
            f"  [bold #7aab7a]✓ {len(new)} new entries added → {target} "
            f"({len(all_entries)} total)[/bold #7aab7a]\n"
        )

    # ────────────────────────────────────────────── crack-secrets

    def _strip_proto_prefix(self, line: str) -> str:
        """Strip nxc-style 'SMB   <ip> <port>   <hostname>   ' line prefixes."""
        m = _PROTO_PREFIX_RE.match(line)
        return m.group(1) if m else line

    def _merge_append(self, target: Path, new_entries: list[str]) -> int:
        """Append unique entries to target, deduplicating in place (push-file logic)."""
        seen: set[str] = set()
        existing: list[str] = []
        if target.exists():
            for line in target.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and line not in seen:
                    existing.append(line)
                    seen.add(line)
        added = 0
        for e in new_entries:
            e = e.strip()
            if e and e not in seen:
                existing.append(e)
                seen.add(e)
                added += 1
        target.write_text("\n".join(existing) + ("\n" if existing else ""), encoding="utf-8")
        return added

    def crack_secrets(self, regdump_file: str):
        """Parse secretsdump / nxc --sam --lsa output, extract creds, crack with hashcat."""
        self.console.rule("[bold #7aab7a]  Secrets Dump Analysis  ", style="#30363d")
        path = Path(regdump_file)
        if not path.exists():
            self.console.print(f"  [red]File not found: {regdump_file}[/red]\n")
            return

        sam_entries: list[tuple[str, str]] = []   # (username, nthash) — SAM/local hashes
        seen_sam_users: set[str] = set()
        dcc_users: set[str] = set()                # cached domain logon usernames
        cleartext: list[tuple[str, str]] = []      # (username_or_'', password) — DefaultPassword

        in_default_pw = False
        for raw_line in path.read_text(errors="replace").splitlines():
            line = self._strip_proto_prefix(raw_line.strip())
            if not line:
                continue

            if "[*] DefaultPassword" in line:
                in_default_pw = True
                continue
            if in_default_pw:
                in_default_pw = False
                m = _DEFAULT_PW_RE.match(line)
                if m:
                    user, pw = m.group(1).strip(), m.group(2).strip()
                    if user.lower() == "(unknown user)":
                        cleartext.append(("", pw))
                    else:
                        cleartext.append((user.split("\\")[-1].split("/")[-1], pw))
                continue

            m = _SAM_LINE_RE.search(line)
            if m:
                user, nt = m.group(1).strip(), m.group(2).lower()
                if not user.endswith("$") and user not in seen_sam_users:
                    sam_entries.append((user, nt))
                    seen_sam_users.add(user)
                continue

            m = _DCC_LINE_RE.search(line)
            if m:
                dcc_users.add(m.group(1).strip())
                continue

        if not sam_entries and not dcc_users and not cleartext:
            self.console.print("  [dim]  No credentials found in file.[/dim]\n")
            return

        crackable = [(u, h) for u, h in sam_entries if h != _EMPTY_NT]

        if sam_entries:
            self.console.print(
                f"\n  [bold #7aab7a]✓ {len(sam_entries)} account(s) found "
                f"({len(crackable)} with real hash)[/bold #7aab7a]"
            )
            t = self._make_table()
            t.add_column("Username", style="bold #e6edf3")
            t.add_column("NT Hash", style="#8b949e")
            t.add_column("Status", style="#7aab7a")
            for u, h in sam_entries:
                status = "[dim]blank/disabled[/dim]" if h == _EMPTY_NT else "●"
                t.add_row(u, h if h != _EMPTY_NT else "[dim]31d6cfe0...(empty)[/dim]", status)
            self.console.print(t)
            self.console.print()

        if dcc_users:
            self.console.print(
                f"  [dim #8b949e]  + {len(dcc_users)} cached domain logon (DCC2) "
                f"account(s): {', '.join(sorted(dcc_users))}[/dim #8b949e]\n"
            )

        cracked: dict[str, str] = {}
        if crackable:
            stem = path.stem
            hash_path = Path(f"{stem}.ntlm.hash")
            user_path = Path(f"{stem}.users.txt")
            hash_path.write_text("\n".join(h for _, h in crackable) + "\n", encoding="utf-8")
            user_path.write_text("\n".join(u for u, _ in sam_entries) + "\n", encoding="utf-8")
            self.console.print(
                f"  [dim #8b949e]  Hashes → {hash_path}   Users → {user_path}[/dim #8b949e]\n"
            )
            cracked = self.crack_ntlm(str(hash_path), user_map={h: u for u, h in crackable})
        elif sam_entries:
            self.console.print("  [dim]  No real NT hashes to export.[/dim]\n")

        # ── consolidate into the shared passwords.txt / ntlmhash.txt / users.txt ──
        all_users = sorted({u for u, _ in sam_entries} | dcc_users
                           | {u for u, _ in cleartext if u})
        ntlm_hashes = [h for _, h in sam_entries if h != _EMPTY_NT]
        passwords = [pw for _, pw in cleartext] + list(cracked.values())

        merged = []
        if all_users:
            n = self._merge_append(Path("users.txt"), all_users)
            merged.append(f"users.txt (+{n})")
        if ntlm_hashes:
            n = self._merge_append(Path("ntlmhash.txt"), ntlm_hashes)
            merged.append(f"ntlmhash.txt (+{n})")
        if passwords:
            n = self._merge_append(Path("passwords.txt"), passwords)
            merged.append(f"passwords.txt (+{n})")
        if merged:
            self.console.print(f"  [dim #8b949e]  ↳ merged → {'  ·  '.join(merged)}[/dim #8b949e]\n")

    def parse_mimikatz(self, dump_file: str):
        self.console.rule("[bold #7aab7a]  Mimikatz Dump Analysis  ", style="#30363d")
        path = Path(dump_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {dump_file}[/red]\n")
            return

        content = path.read_text(errors="replace")
        entries = self._extract_entries(content)

        if not entries:
            self.console.print("[dim]  No credentials found in dump.[/dim]\n")
            return

        # Separate cleartext vs hash-only entries for cleaner display
        cleartext = [e for e in entries if e.get("password")]
        hash_only = [e for e in entries if not e.get("password") and e.get("ntlm")]

        self.console.print(
            f"\n  [bold #7aab7a]✓ {len(entries)} credential set(s) found "
            f"([#c9a96e]{len(cleartext)} cleartext[/#c9a96e] / "
            f"[#8b949e]{len(hash_only)} hash-only[/#8b949e])[/bold #7aab7a]\n"
        )

        if cleartext:
            self.console.print("  [bold #c9a96e]Cleartext Passwords[/bold #c9a96e]")
            t = self._make_table()
            t.add_column("Username", style="bold #e6edf3")
            t.add_column("Domain", style="#7aab7a")
            t.add_column("Password", style="#c9a96e")
            t.add_column("Source", style="#8b7aa8")
            for e in cleartext:
                t.add_row(e["username"], e.get("domain", "—"), e["password"], e.get("source", "—"))
            self.console.print(t)
            self.console.print()

        if hash_only:
            self.console.print("  [bold #8b949e]NTLM Hashes[/bold #8b949e]")
            t = self._make_table()
            t.add_column("Username", style="bold #e6edf3")
            t.add_column("Domain", style="#7aab7a")
            t.add_column("NTLM Hash", style="#8b949e")
            t.add_column("Source", style="#8b7aa8")
            for e in hash_only:
                t.add_row(e["username"], e.get("domain", "—"), e["ntlm"], e.get("source", "—"))
            self.console.print(t)
            self.console.print()

        # Export mimi_users.txt and mimi_ntlm.hash to cwd
        users_path = Path.cwd() / "mimi_users.txt"
        hash_path2 = Path.cwd() / "mimi_ntlm.hash"
        all_users = sorted({e["username"] for e in entries})
        users_path.write_text("\n".join(all_users) + "\n", encoding="utf-8")
        ntlm_list = [e["ntlm"] for e in entries if e.get("ntlm")]
        if ntlm_list:
            hash_path2.write_text("\n".join(ntlm_list) + "\n", encoding="utf-8")
            self.console.print(
                f"  [dim #8b949e]  → {users_path}  {hash_path2}[/dim #8b949e]\n"
            )
        else:
            self.console.print(
                f"  [dim #8b949e]  → {users_path}  (no NTLM hashes to export)[/dim #8b949e]\n"
            )

        # ── consolidate into the shared passwords.txt / ntlmhash.txt / users.txt ──
        merged = []
        if all_users:
            n = self._merge_append(Path("users.txt"), all_users)
            merged.append(f"users.txt (+{n})")
        if ntlm_list:
            n = self._merge_append(Path("ntlmhash.txt"), ntlm_list)
            merged.append(f"ntlmhash.txt (+{n})")
        passwords = [e["password"] for e in cleartext]
        if passwords:
            n = self._merge_append(Path("passwords.txt"), passwords)
            merged.append(f"passwords.txt (+{n})")
        if merged:
            self.console.print(f"  [dim #8b949e]  ↳ merged → {'  ·  '.join(merged)}[/dim #8b949e]\n")

    def _make_table(self) -> Table:
        return Table(
            box=box.SIMPLE_HEAD,
            border_style="#30363d",
            header_style="bold #c9a96e",
            show_edge=False,
            padding=(0, 1),
        )

    # ============================================================ NEW PARSERS
    # Replaces all previous parser methods with two format-specific ones.

    def _extract_entries(self, content: str) -> list[dict]:
        """
        Unified parser for:
        - pypykatz format  (== LogonSession == / == MSV == / == Kerberos ==)
        - classic mimikatz (Authentication Id : / msv : / * Username :)
        - lsadump::sam     (User : / Hash NTLM:)
        - lsadump::dcsync  (SAM Username : / Hash NTLM:)
        """
        raw: list[dict] = []
        raw += self._parse_pypykatz(content)
        raw += self._parse_classic(content)
        raw += self._parse_sam(content)
        raw += self._parse_dcsync(content)

        # Merge duplicates by (username_lower, domain_lower):
        # prefer entries with password; always keep ntlm if available.
        merged: dict[tuple, dict] = {}
        for e in raw:
            key = (e["username"].lower(), e.get("domain", "").lower())
            if key not in merged:
                merged[key] = dict(e)
            else:
                if e.get("password") and not merged[key].get("password"):
                    merged[key]["password"] = e["password"]
                if e.get("ntlm") and not merged[key].get("ntlm"):
                    merged[key]["ntlm"] = e["ntlm"]

        return list(merged.values())

    # ---------------------------------------------------------------- parsers

    _NULL = {"(null)", "null", "none", "na", ""}

    @classmethod
    def _is_junk_password(cls, v: str) -> bool:
        """Return True for machine-account kerberos blobs (long hex or hex bytes)."""
        if not v or v.lower() in cls._NULL:
            return True
        # continuous hex blob (pypykatz format)
        if len(v) > 64 and re.fullmatch(r"[0-9a-fA-F]+", v):
            return True
        # spaced hex bytes (classic mimikatz format: "87 77 a6 62 c5 09 ...")
        if len(v) > 32 and re.fullmatch(r"[0-9a-fA-F]{2}( [0-9a-fA-F]{2})+", v):
            return True
        return False

    @classmethod
    def _is_machine(cls, username: str) -> bool:
        return username.strip().endswith("$") or not username.strip()

    @classmethod
    def _valid_ntlm(cls, v: str) -> bool:
        return bool(v and re.fullmatch(r"[0-9a-fA-F]{32}", v.strip()))

    @classmethod
    def _fval(cls, line: str) -> str:
        """Value after first colon."""
        return line.split(":", 1)[-1].strip() if ":" in line else ""

    def _parse_pypykatz(self, content: str) -> list[dict]:
        """
        pypykatz format:
          == LogonSession ==
          username leon
          domainname MEDTECH
              == MSV ==
                  Username: leon
                  NT: 2e208ad146efda5bc44869025e06544a
              == Kerberos ==
                  Username: leon
                  Password: rabbit:)
                  password (hex)...   <- skip
        """
        results: list[dict] = []
        in_session = False
        session_user = ""
        session_domain = ""
        in_sub = ""
        sub: dict = {}

        def flush():
            if sub.get("username") and not self._is_machine(sub["username"]):
                if sub.get("ntlm") or sub.get("password"):
                    results.append(dict(sub))

        for line in content.splitlines():
            s = line.strip()

            if s == "== LogonSession ==":
                flush()
                in_session = True
                session_user = session_domain = ""
                in_sub = ""
                sub = {}
                continue

            if not in_session:
                continue

            # Top-level session fields (no indentation marker)
            if re.match(r"^username\s+\S", s, re.I) and not s.startswith("=="):
                session_user = s.split(None, 1)[1] if len(s.split(None, 1)) > 1 else ""
                continue
            if re.match(r"^domainname\s+\S", s, re.I):
                session_domain = s.split(None, 1)[1] if len(s.split(None, 1)) > 1 else ""
                continue

            # Sub-module start
            m = re.match(r"^==\s*(MSV|Kerberos|WDIGEST|tspkg|ssp)\s*", s, re.I)
            if m:
                flush()
                in_sub = m.group(1).lower()
                sub = {}
                continue

            if not in_sub:
                continue

            # Skip "password (hex)..." lines
            if re.match(r"^password\s*\(hex\)", s, re.I):
                continue

            # Fields inside sub-module
            if re.match(r"^Username\s*:", s, re.I):
                val = self._fval(s)
                if val and not self._is_machine(val) and val.lower() not in self._NULL:
                    sub["username"] = val
                    sub.setdefault("domain", session_domain)
                    sub["source"] = in_sub
            elif re.match(r"^Domain\s*:", s, re.I):
                val = self._fval(s)
                if val and val.lower() not in self._NULL:
                    sub["domain"] = val
            elif re.match(r"^NT\s*:", s, re.I):
                val = self._fval(s)
                if self._valid_ntlm(val):
                    sub["ntlm"] = val.strip()
            elif re.match(r"^Password\s*:", s, re.I):
                val = self._fval(s)
                if not self._is_junk_password(val):
                    sub["password"] = val

        flush()
        return results

    def _parse_classic(self, content: str) -> list[dict]:
        """
        Classic mimikatz sekurlsa::logonpasswords:
          Authentication Id : 0 ; 682854 ...
          User Name         : Administrator
              msv :
               * Username : Administrator
               * NTLM     : f26c0186...
              kerberos :
               * Password : (null)
        """
        results: list[dict] = []
        in_session = False
        in_sub = ""
        sub: dict = {}
        session_user = ""
        session_domain = ""

        def flush():
            if sub.get("username") and not self._is_machine(sub["username"]):
                if sub.get("ntlm") or sub.get("password"):
                    results.append(dict(sub))

        for line in content.splitlines():
            s = line.strip()

            if re.match(r"^Authentication Id\s*:", s, re.I):
                flush()
                in_session = True
                in_sub = ""
                sub = {}
                session_user = session_domain = ""
                continue

            if not in_session:
                continue

            if re.match(r"^User Name\s*:", s, re.I):
                session_user = self._fval(s)
                continue
            if re.match(r"^Domain\s*:", s, re.I) and not in_sub:
                session_domain = self._fval(s)
                continue

            # Sub-module line (e.g. "        msv :")
            m = re.match(r"^(msv|kerberos|wdigest|tspkg|ssp|credman)\s*:", s, re.I)
            if m:
                flush()
                in_sub = m.group(1).lower()
                sub = {}
                continue

            if not in_sub:
                continue

            # * field lines
            if re.match(r"^\*\s*Username\s*:", s, re.I):
                val = self._fval(s)
                if val and not self._is_machine(val) and val.lower() not in self._NULL:
                    sub["username"] = val
                    sub.setdefault("domain", session_domain)
                    sub["source"] = in_sub
            elif re.match(r"^\*\s*Domain\s*:", s, re.I):
                val = self._fval(s)
                if val and val.lower() not in self._NULL:
                    sub["domain"] = val
            elif re.match(r"^\*\s*NTLM\s*:", s, re.I):
                val = self._fval(s)
                if self._valid_ntlm(val):
                    sub["ntlm"] = val.strip()
            elif re.match(r"^\*\s*Password\s*:", s, re.I):
                val = self._fval(s)
                if not self._is_junk_password(val):
                    sub["password"] = val

        flush()
        return results

    def _parse_sam(self, content: str) -> list[dict]:
        """lsadump::sam: User : / Hash NTLM:"""
        results: list[dict] = []
        cur: dict = {}
        for line in content.splitlines():
            s = line.strip()
            if re.match(r"^User\s*:", s, re.I):
                if cur.get("username") and cur.get("ntlm"):
                    results.append(cur)
                val = self._fval(s)
                cur = {"username": val, "source": "sam"} if val and not self._is_machine(val) else {}
            elif re.match(r"^Hash NTLM\s*:", s, re.I) and cur:
                val = self._fval(s)
                if self._valid_ntlm(val):
                    cur["ntlm"] = val.strip()
        if cur.get("username") and cur.get("ntlm"):
            results.append(cur)
        return results

    def _parse_dcsync(self, content: str) -> list[dict]:
        """lsadump::dcsync: SAM Username / Credentials: / Hash NTLM"""
        results: list[dict] = []
        cur: dict = {}
        in_creds = False
        for line in content.splitlines():
            s = line.strip()
            if re.match(r"^SAM Username\s*:", s, re.I):
                if cur.get("username") and cur.get("ntlm"):
                    results.append(cur)
                val = self._fval(s)
                cur = {"username": val, "source": "dcsync"} if val and not self._is_machine(val) else {}
                in_creds = False
            elif re.match(r"^Credentials\s*:", s, re.I):
                in_creds = True
            elif in_creds and re.match(r"^Hash NTLM\s*:", s, re.I) and cur:
                val = self._fval(s)
                if self._valid_ntlm(val):
                    cur["ntlm"] = val.strip()
        if cur.get("username") and cur.get("ntlm"):
            results.append(cur)
        return results

    # ============================================================ PEAS PARSERS

    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

    @classmethod
    def _strip_ansi(cls, text: str) -> str:
        return cls._ANSI_RE.sub("", text)

    # ---- WinPEAS -------------------------------------------------------

    _WINPEAS_RULES: list[tuple[str, str, str]] = [
        ("AlwaysInstallElevated",
         r"AlwaysInstallElevated.*(1|enabled|Yes)",
         "MSI installer runs as SYSTEM"),
        ("Token Privilege",
         r"(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeDebugPrivilege"
         r"|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege)",
         "Potato / token impersonation"),
        ("Unquoted Service Path",
         r"(No quotes and space detected|Unquoted.*service.*path)",
         "Place binary at truncated path"),
        ("Writable Service",
         r"(You can modify.*binary|FILE_ALL_ACCESS.*service|Write.*service.*binary"
         r"|Permissions.*service.*Write)",
         "Replace/modify service binary"),
        ("Autologon",
         r"(DefaultUserName|DefaultPassword|AutoAdminLogon\s*=\s*1)",
         "Cleartext creds in registry"),
        ("LAPS",
         r"(LAPS.*[Pp]assword|AdmPwd\s*=|LAPSAdmName)",
         "LAPS admin password readable"),
        ("Scheduled Task",
         r"(Task To Run:.*\.(bat|ps1|vbs|exe)|task.*writable|You can modify.*task)",
         "Writable scheduled task target"),
        ("Stored Credential",
         r"(cmdkey.*list|Target:.*Domain|saved.*cred|DPAPI.*masterkey)",
         "Windows credential vault"),
        ("PATH Hijack",
         r"(Interesting.*PATH.*writable|writable.*PATH.*folder)",
         "Drop DLL/EXE in writable PATH dir"),
        ("Password in Registry",
         r"(?i)(password|passwd|pwd)\s*[=:]\s*(?!\*{3}|null|\s*$)\S{3}",
         "Cleartext password found"),
    ]

    def parse_winpeas(self, dump_file: str):
        """Parse WinPEAS output and surface OSCP-relevant privesc findings."""
        self.console.rule("[bold #f85149]  WinPEAS Analysis  ", style="#30363d")
        path = Path(dump_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {dump_file}[/red]\n")
            return

        lines = self._strip_ansi(path.read_text(errors="replace")).splitlines()
        findings: list[tuple[str, str, str]] = []
        seen: set[tuple] = set()

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            for cat, pattern, note in self._WINPEAS_RULES:
                if re.search(pattern, stripped, re.I):
                    key = (cat, stripped[:80])
                    if key not in seen:
                        seen.add(key)
                        findings.append((cat, stripped[:120], note))

        if not findings:
            self.console.print("[dim]  No critical findings detected.[/dim]\n")
            return

        self.console.print(
            f"\n  [bold #f85149]⚠ {len(findings)} finding(s)[/bold #f85149]\n"
        )
        t = self._make_table()
        t.add_column("Category", style="bold #c9a96e", min_width=22)
        t.add_column("Matched Line", style="#c0c8d4", max_width=60)
        t.add_column("Note", style="#8b7aa8", max_width=42)
        for cat, line_text, note in findings:
            t.add_row(cat, line_text, note)
        self.console.print(t)
        self.console.print()

    # ---- LinPEAS -------------------------------------------------------

    _SUID_INTERESTING = {
        "find", "vim", "vi", "python", "python3", "perl", "ruby", "bash", "sh",
        "nmap", "awk", "more", "less", "man", "cp", "mv", "nano", "tee",
        "env", "node", "php", "curl", "wget", "openssl", "tar", "zip",
        "base64", "base32", "git", "nc", "netcat", "gdb", "strace", "ltrace",
        "ftp", "ssh", "scp", "rsync", "docker", "screen", "tmux", "mysql",
        "passwd", "chsh", "chfn", "newgrp", "pkexec", "doas", "sudo",
    }

    _LINPEAS_RULES: list[tuple[str, str, str]] = [
        ("Sudo NOPASSWD",
         r"NOPASSWD",
         "sudo without password"),
        ("NFS no_root_squash",
         r"no_root_squash",
         "Mount NFS as root → privesc"),
        ("Writable Sensitive File",
         r"(-rw-rw-rw-|-rwxrwxrwx).*(/etc/passwd|/etc/shadow|/etc/sudoers)",
         "World-writable sensitive file"),
        ("Capability",
         r"cap_setuid\+ep|cap_sys_admin\+ep|cap_net_raw\+ep|cap_dac_read_search",
         "Linux capability privesc"),
        ("PATH Writable",
         r"(Writable.*PATH|PATH.*writable|writable.*in.*PATH)",
         "PATH injection opportunity"),
        ("Cron Writable",
         r"(cron.*writable|You can write.*cron|writable.*cron|crontab.*write)",
         "Modify cron script for RCE"),
        ("SSH Private Key",
         r"(-----BEGIN.*PRIVATE KEY|id_rsa|id_ecdsa|id_ed25519)",
         "SSH private key found"),
        ("Password in File",
         r"(?i)(password|passwd|secret)\s*[=:]\s*(?!\*{3}|null|\s*$)\S{4}",
         "Cleartext credential in file"),
        ("Docker/LXC Socket",
         r"(docker.*socket|lxc.*container|/var/run/docker\.sock)",
         "Container escape possible"),
    ]

    def parse_linpeas(self, dump_file: str):
        """Parse LinPEAS output and surface OSCP-relevant privesc findings."""
        self.console.rule("[bold #f85149]  LinPEAS Analysis  ", style="#30363d")
        path = Path(dump_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {dump_file}[/red]\n")
            return

        text = self._strip_ansi(path.read_text(errors="replace"))
        lines = text.splitlines()
        findings: list[tuple[str, str, str]] = []
        seen: set[tuple] = set()

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            for cat, pattern, note in self._LINPEAS_RULES:
                if re.search(pattern, stripped, re.I):
                    key = (cat, stripped[:80])
                    if key not in seen:
                        seen.add(key)
                        findings.append((cat, stripped[:120], note))

        # SUID scan: filter to interesting binaries
        in_suid = False
        for line in lines:
            if re.search(r"SUID.*(binaries|files)|Find.*SUID", line, re.I):
                in_suid = True
                continue
            if in_suid:
                if re.match(r"^[╔══]", line):
                    in_suid = False
                    continue
                m = re.search(r"[-/](\w+)\s*$", line.strip())
                if m and m.group(1).lower() in self._SUID_INTERESTING:
                    binary = m.group(1).lower()
                    key = ("SUID Binary", line.strip()[:80])
                    if key not in seen:
                        seen.add(key)
                        findings.append(("SUID Binary", line.strip()[:120],
                                         f"{binary} — check GTFOBins"))

        if not findings:
            self.console.print("[dim]  No critical findings detected.[/dim]\n")
            return

        self.console.print(
            f"\n  [bold #f85149]⚠ {len(findings)} finding(s)[/bold #f85149]\n"
        )
        t = self._make_table()
        t.add_column("Category", style="bold #c9a96e", min_width=22)
        t.add_column("Matched Line", style="#c0c8d4", max_width=60)
        t.add_column("Note", style="#8b7aa8", max_width=42)
        for cat, line_text, note in findings:
            t.add_row(cat, line_text, note)
        self.console.print(t)
        self.console.print()

    # ============================================================ NET USER / FEROX PARSERS

    def parse_net_users(self, input_file: str, output_file: str):
        """Parse 'net user /domain' output → clean users.txt."""
        self.console.rule("[bold #7aab7a]  Net User Parser  ", style="#30363d")
        path = Path(input_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {input_file}[/red]\n")
            return

        content = path.read_text(errors="replace")
        users: list[str] = []
        # Skip header lines: "User accounts for ...", "---...", "The command completed..."
        in_users = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"^-{10,}", stripped):
                in_users = True
                continue
            if not in_users:
                continue
            if re.match(r"The command completed", stripped, re.I):
                break
            # Each line can contain up to 3 space-separated usernames (25-char columns)
            for token in re.split(r"\s{2,}", stripped):
                tok = token.strip()
                if tok and not re.match(r"^\s*$", tok):
                    users.append(tok)

        if not users:
            self.console.print("[dim]  No users found in file.[/dim]\n")
            return

        out = Path(output_file)
        out.write_text("\n".join(users) + "\n", encoding="utf-8")
        self.console.print(
            f"\n  [bold #7aab7a]✓ {len(users)} users → {out}[/bold #7aab7a]\n"
        )
        t = self._make_table()
        t.add_column("Username", style="bold #e6edf3")
        for u in users:
            t.add_row(u)
        self.console.print(t)
        self.console.print()

    def parse_web_log(self, log_file: str, output_file: str | None = None):
        """Parse feroxbuster/gobuster log → directory tree display."""
        self.console.rule("[bold #7aab7a]  Web Log Parser  ", style="#30363d")
        path = Path(log_file)
        if not path.exists():
            self.console.print(f"[red]  File not found: {log_file}[/red]\n")
            return

        content = path.read_text(errors="replace")
        # Parse lines: feroxbuster "STATUS  METHOD  LINES  WORDS  CHARS  URL"
        # or gobuster "STATUS  URL"
        entries: list[tuple[int, str]] = []
        for line in content.splitlines():
            # feroxbuster format: "200  GET  N  N  N  http://..."
            m = re.match(r"(\d{3})\s+(?:GET|POST|HEAD)\s+\S+\s+\S+\s+\S+\s+(https?://\S+)", line)
            if m:
                entries.append((int(m.group(1)), m.group(2)))
                continue
            # gobuster format: "/path (Status: 200) [Size: 123]"
            m2 = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if m2:
                entries.append((int(m2.group(2)), m2.group(1)))
                continue
            # simple URL line
            m3 = re.match(r"(https?://\S+)", line)
            if m3:
                entries.append((0, m3.group(1)))

        if not entries:
            self.console.print("[dim]  No URL entries found in log.[/dim]\n")
            return

        # Extract paths and build tree
        from urllib.parse import urlparse
        paths: dict[str, int] = {}
        base_url = ""
        for code, url in entries:
            parsed = urlparse(url)
            if not base_url and parsed.scheme:
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            path_only = parsed.path.rstrip("/") or "/"
            paths[path_only] = code

        # Build tree structure
        tree: dict = {}
        for p in sorted(paths):
            parts = [x for x in p.split("/") if x]
            node = tree
            for part in parts:
                node = node.setdefault(part, {})

        _INTERESTING = {
            "admin", "administrator", "api", "login", "panel", "dashboard",
            "backup", "config", "upload", "uploads", "shell", "cmd", "exec",
            "phpmyadmin", "wp-admin", "manager", "console", "debug", "test",
            "secret", "private", "hidden", "cgi-bin", "setup", "install",
        }

        def _render_tree(node: dict, prefix: str = "", path_so_far: str = "") -> list[str]:
            lines_out = []
            items = sorted(node.items())
            for i, (name, children) in enumerate(items):
                is_last = (i == len(items) - 1)
                connector = "└── " if is_last else "├── "
                full_path = f"{path_so_far}/{name}"
                code = paths.get(full_path, paths.get(full_path + "/", 0))
                code_str = f"[{code}]" if code else ""
                flag = " ★" if name.lower() in _INTERESTING else ""
                lines_out.append(f"{prefix}{connector}{name}/{code_str}{flag}")
                extension = "    " if is_last else "│   "
                lines_out.extend(_render_tree(children, prefix + extension, full_path))
            return lines_out

        tree_lines = [base_url or "/"] + _render_tree(tree)
        tree_text = "\n".join(tree_lines)

        self.console.print(
            f"\n  [bold #7aab7a]✓ {len(paths)} unique paths[/bold #7aab7a]"
        )
        self.console.print(f"\n[dim #8b949e]{tree_text}[/dim #8b949e]\n")

        if output_file:
            out = Path(output_file)
            if out.suffix.lower() == ".html":
                html = self._build_explorer_standalone_html(paths, base_url, log_file)
                out.write_text(html, encoding="utf-8")
                self.console.print(f"  [bold #7aab7a]✓ HTML report → {out}[/bold #7aab7a]\n")
            else:
                out.write_text(tree_text + "\n", encoding="utf-8")
                self.console.print(f"  [dim #8b949e]  Tree → {out}[/dim #8b949e]\n")

    def _build_explorer_standalone_html(self, paths: dict, base_url: str, source_file: str) -> str:
        """Generate a self-contained HTML file with the interactive directory explorer."""
        from datetime import datetime as _dt
        total = len(paths)
        _INTERESTING = {
            "admin", "administrator", "api", "login", "panel", "dashboard",
            "backup", "config", "upload", "uploads", "shell", "cmd", "exec",
            "phpmyadmin", "wp-admin", "wp-content", "manager", "console", "debug",
            "test", "secret", "private", "hidden", "cgi-bin", "setup", "install",
            "cms", "data", "password", "passwd", "credentials", "keys", "token", "auth",
        }
        _ICONS = {
            "php": "⚡", "asp": "⚡", "aspx": "⚡", "jsp": "⚡", "cgi": "⚡",
            "py": "⚡", "rb": "⚡", "pl": "⚡", "sh": "⚡",
            "html": "🌐", "htm": "🌐",
            "txt": "📝", "md": "📝", "conf": "📝", "config": "📝", "cfg": "📝",
            "ini": "📝", "env": "📝", "xml": "📝", "json": "📝", "yaml": "📝",
            "js": "📜", "css": "🎨",
            "zip": "📦", "tar": "📦", "gz": "📦", "7z": "📦", "bak": "💾",
            "jpg": "🖼", "jpeg": "🖼", "png": "🖼", "gif": "🖼", "svg": "🖼",
            "pdf": "📑", "sql": "🗄", "db": "🗄",
        }

        def _icon(name: str, is_dir: bool) -> str:
            if is_dir:
                return "📁"
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            return _ICONS.get(ext, "📄")

        def _badge(code: int) -> str:
            if not code:
                return ""
            col = {"2": "#7aab7a", "3": "#c9a96e", "4": "#8b949e", "5": "#f85149"}.get(str(code)[0], "#8b949e")
            return (
                f'<span style="font-size:10px;padding:1px 5px;border-radius:10px;'
                f'background:{col}22;border:1px solid {col}55;color:{col};flex-shrink:0">{code}</span>'
            )

        # Build trie
        tree: dict = {}
        for p in sorted(paths):
            node = tree
            for part in [x for x in p.split("/") if x]:
                node = node.setdefault(part, {})

        def _node_html(node: dict, path_so_far: str = "") -> str:
            html = ""
            for name, children in sorted(node.items()):
                full_path = f"{path_so_far}/{name}"
                code = paths.get(full_path, paths.get(full_path + "/", 0))
                is_dir = bool(children)
                is_int = name.lower() in _INTERESTING
                icon = _icon(name, is_dir)
                badge = _badge(code)
                star = '<span style="color:#f0883e;font-size:10px;flex-shrink:0">★</span>' if is_int else ""
                name_col = "#f0883e" if is_int else "#c0c8d4"
                fw = "font-weight:600;" if is_int else ""
                link = (
                    f'<a href="{base_url}{full_path}" target="_blank" onclick="event.stopPropagation()" '
                    f'style="color:#656d76;font-size:11px;text-decoration:none;padding:0 3px;'
                    f'border-radius:3px;flex-shrink:0" title="{base_url}{full_path}">↗</a>'
                ) if base_url else ""
                row_style = "display:flex;align-items:center;gap:5px;padding:3px 8px;white-space:nowrap;overflow:hidden"
                name_style = (
                    f"font-family:monospace;font-size:12px;color:{name_col};{fw}"
                    f"flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis"
                )
                if is_dir:
                    child_html = _node_html(children, full_path)
                    html += (
                        f'<details data-path="{full_path}" open style="border:none">'
                        f'<summary style="{row_style};cursor:pointer;list-style:none;border-radius:4px;transition:background .1s"'
                        f' onmouseover="this.style.background=\'#21262d\'"'
                        f' onmouseout="this.style.background=\'\'">'
                        f'<span style="font-size:9px;color:#656d76;width:10px;flex-shrink:0">▼</span>'
                        f'<span style="font-size:13px;flex-shrink:0">{icon}</span>'
                        f'<span style="{name_style}">{name}/</span>'
                        f'{star}{badge}{link}'
                        f'</summary>'
                        f'<div style="padding-left:20px;border-left:1px solid #30363d;margin-left:14px">'
                        f'{child_html}</div></details>'
                    )
                else:
                    html += (
                        f'<div data-path="{full_path}" style="{row_style};border-radius:4px;transition:background .1s"'
                        f' onmouseover="this.style.background=\'#21262d\'"'
                        f' onmouseout="this.style.background=\'\'">'
                        f'<span style="width:10px;flex-shrink:0"></span>'
                        f'<span style="font-size:13px;flex-shrink:0">{icon}</span>'
                        f'<span style="{name_style}">{name}</span>'
                        f'{star}{badge}{link}'
                        f'</div>'
                    )
            return html

        inner = _node_html(tree)
        now = _dt.now().strftime("%Y-%m-%d %H:%M")
        src_esc = source_file.replace('"', "&quot;")
        base_esc = base_url.replace('"', "&quot;")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxenum web — {src_esc}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
      --text:#c0c8d4;--muted:#8b949e;--gold:#c9a96e;--sage:#7aab7a;
      --font:system-ui,sans-serif;--mono:'Cascadia Code','Fira Code',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh}}
.header{{background:var(--bg2);border-bottom:1px solid var(--border);padding:16px 24px;
         display:flex;align-items:center;gap:12px}}
.title{{font-size:16px;font-weight:700;color:var(--gold)}}
.subtitle{{font-size:12px;color:var(--muted)}}
.container{{padding:24px;max-width:1100px;margin:0 auto}}
.tree-wrap{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
.toolbar{{display:flex;align-items:center;gap:8px;padding:8px 12px;
          border-bottom:1px solid var(--border);background:var(--bg3);flex-wrap:wrap}}
input[type=text]{{flex:1;min-width:160px;background:var(--bg);border:1px solid var(--border);
                  border-radius:6px;padding:5px 10px;color:var(--text);font-size:12px;outline:none;
                  font-family:var(--mono)}}
button{{background:none;border:1px solid var(--border);color:var(--muted);font-size:11px;
        padding:4px 8px;border-radius:6px;cursor:pointer;font-family:var(--font)}}
button:hover{{border-color:#656d76;color:var(--text)}}
#tree{{padding:6px 4px;max-height:calc(100vh - 160px);overflow-y:auto}}
details>summary::-webkit-details-marker{{display:none}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="title">◈ Web Directory Explorer</div>
    <div class="subtitle">{src_esc} · {total} paths · {now}</div>
  </div>
</div>
<div class="container">
  <div class="tree-wrap">
    <div class="toolbar">
      <input type="text" id="filter" placeholder="🔍 Filter paths..." oninput="filterTree(this)">
      <button onclick="expandAll()">＋ Expand all</button>
      <button onclick="collapseAll()">－ Collapse all</button>
      <span style="color:#656d76;font-size:11px;white-space:nowrap">{total} paths</span>
      <span style="color:#8b949e;font-size:11px;flex:1;text-align:right;overflow:hidden;
            text-overflow:ellipsis;white-space:nowrap">{base_esc}</span>
    </div>
    <div id="tree">{inner}</div>
  </div>
</div>
<script>
function filterTree(inp){{
  var q=inp.value.trim().toLowerCase();
  var tree=document.getElementById('tree');
  var all=Array.from(tree.querySelectorAll('[data-path]'));
  if(!q){{
    all.forEach(function(el){{el.style.display='';}});
    tree.querySelectorAll('details').forEach(function(d){{d.open=d.dataset.wasopen!=='0';}});
    return;
  }}
  tree.querySelectorAll('details').forEach(function(d){{
    if(d.dataset.wasopen===undefined)d.dataset.wasopen=d.open?'1':'0';
    d.open=true;
  }});
  var vis=new Set();
  all.forEach(function(el){{if(el.dataset.path.toLowerCase().includes(q))vis.add(el.dataset.path);}});
  var extra=[];
  vis.forEach(function(p){{
    var parts=p.split('/');
    for(var i=1;i<=parts.length;i++)extra.push(parts.slice(0,i).join('/')||'/');
  }});
  extra.forEach(function(p){{vis.add(p);}});
  all.forEach(function(el){{el.style.display=vis.has(el.dataset.path)?'':'none';}});
}}
function expandAll(){{document.getElementById('tree').querySelectorAll('details').forEach(function(d){{d.open=true;}});}}
function collapseAll(){{document.getElementById('tree').querySelectorAll('details').forEach(function(d){{d.open=false;}});}}
</script>
</body>
</html>"""
