Here is the complete English translation of your document, formatted as a clean, scannable Markdown block.

```markdown
# 🔍 proxenum — Automated Enumeration Suite

> **scan · focus · drill · stax**

---

## 📖 Overview

**proxenum** is an automated enumeration suite written in Python, specifically tailored for real-world penetration testing.  
It covers the entire reconnaissance lifecycle across 4 distinct modes—ranging from initial target enumeration and vulnerability scanning to credential cracking and static analysis.

| Mode | Use Case | Primary Target |
|--------|------|---------|
| `scan` | Multi-host bulk enumeration | SMB + Nmap + Password Spraying |
| `focus` | Deep dive into a single IP | All ports + Detailed service-specific enumeration |
| `drill` | Automated scoring + Deep dive | Multiple hosts → Automatically executes `focus` on Top N |
| `stax` | Static analysis utility | Hash cracking, log parsing, and file manipulation |

Upon startup, a random motivational quote (English + Japanese translation) is displayed to give you a quick moment of zen.

---

## 🛠️ Installation & Dependencies

### Python Dependencies

```bash
pip install -r requirements.txt
# Only requires rich>=13.0.0

```

### External Tools

The following tools must be installed on your system.

Any missing tools will be skipped automatically without throwing errors.

| Tool | Purpose | Installation Example |
| --- | --- | --- |
| `nmap` | Port scanning & vulnerability detection | `apt install nmap` |
| `rustscan` | Fast asynchronous port discovery | [rustscan releases](https://github.com/RustScan/RustScan) |
| `nxc` / `netexec` | SMB/WinRM/LDAP/FTP enumeration | `pipx install netexec` |
| `feroxbuster` | Web content discovery (Directory brute-forcing) | `apt install feroxbuster` |
| `ffuf` | Vhost fuzzing | `apt install ffuf` |
| `hashcat` | NTLM hash cracking | `apt install hashcat` |
| `whatweb` | Web technology fingerprinting | `apt install whatweb` |
| `searchsploit` | Exploit DB search | `apt install exploitdb` |
| `davtest` | WebDAV detection & testing | `apt install davtest` |
| `enum4linux-ng` | Detailed SMB/LDAP enumeration | `apt install enum4linux-ng` |
| `ldapsearch` | LDAP querying | `apt install ldap-utils` |
| `smbclient` | SMB share connection | `apt install smbclient` |
| `xsltproc` | Nmap XML to HTML conversion | `apt install xsltproc` |
| `impacket` | AS-REP / Kerberoasting toolset | `pipx install impacket` |
| `redis-cli` | Redis enumeration | `apt install redis-tools` |

### Wordlists (Recommended)

```bash
# SecLists (For feroxbuster / ffuf)
apt install seclists
# rockyou.txt (For hashcat)
gunzip /usr/share/wordlists/rockyou.txt.gz

```

---

## 🚀 Basic Usage

```bash
python3 proxenum.py <mode> [options]
# OR
chmod +x proxenum.py
./proxenum.py <mode> [options]

```

---

## 🟢 scan Mode

A bulk enumeration mode designed for multi-host targets. For a specified IP list (or subnet), it sequentially runs SMB enumeration → Port scanning → Password spraying → Additional detailed enumeration.

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. nxc smb — Gather SMB info (hostname / domain / signing)       │
│ 2. rustscan → nmap -p- → nmap -sCV (All TCP ports)              │
│ 3. nxc smb / winrm — Password spraying (Optional)               │
│ 4. Anonymous SMB shares / LDAP enum & AS-REP Roasting (Optional) │
│ 5. Authenticated SMB/LDAP enum + Kerberoasting (Post-credential)│
│ 6. Generate scan_N.html report                                  │
└─────────────────────────────────────────────────────────────────┘

```

### Options

| Option | Description |
| --- | --- |
| `-i IP/FILE` | Target IP (Single IP, CIDR, or file path) **[Required]** |
| `-u USER/FILE` | Username (Single username or file path) |
| `-p PASS/FILE` | Password (Single password or file path; requires `-u`) |
| `-n HASH/FILE` | NTLM hash (Single hash or file path; requires `-u`) |
| `--proxy` | Route all commands through `proxychains4 -q` (SOCKS pivoting) |
| `--ligolo` | Route through ligolo-ng TUN interface (Conservative timing) |
| `--top-ports N` | Fast mode: Scan only top N ports (Skips rustscan / -p-) |
| `--no-portscan` | Skip port scanning |
| `--no-report` | Do not generate an HTML report (CLI output only) |
| `--new-log` | Force-create a new proxscan log file |
| `--skip-log` | Completely skip reading or writing proxscan logs |
| `--no-brute` | Pass `--no-brute` to nxc (1:1 user-to-password pairing) |
| `--continue-on-success` | Continue password spraying even after a successful auth |
| `--local-auth` | Use `nxc --local-auth` |

### Examples

```bash
# Basic scan (IP file + User file + Password file)
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt

# Over a SOCKS proxy (Using chisel / proxychains)
python3 proxenum.py scan -i ip.txt --proxy

# Over a ligolo-ng tunnel
python3 proxenum.py scan -i ip.txt --ligolo

# Fast mode: Scan only the top 100 ports
python3 proxenum.py scan -i ip.txt --top-ports 100

# Password spray using NTLM hashes
python3 proxenum.py scan -i ip.txt -u users.txt -n hashes.txt

# Single IP, skip report generation
python3 proxenum.py scan -i 10.10.10.5 --no-report

# Reuse port data from an existing log file (Skip re-scanning)
python3 proxenum.py scan -i ip.txt -u users.txt -p passwords.txt
# -> Automatically reads proxscan.1.json if it exists and skips port scanning

# Force creation of a fresh log file
python3 proxenum.py scan -i ip.txt --new-log

```

### Differences: --proxy vs --ligolo

| Feature | `--proxy` | `--ligolo` |
| --- | --- | --- |
| Connection Method | Via `proxychains4 -q` | Direct TUN interface |
| SYN Scan | No (TCP Connect `-sT` only) | Yes |
| rustscan | Skipped | Used (Low-rate settings) |
| Full Scan | Top-30 ports only | All ports (Low-rate) |
| Target Use Case | Chisel SOCKS pivot | ligolo-ng already set up |

---

## 🟡 focus Mode

A deep-dive enumeration mode for a single IP. It runs `rustscan` + `nmap -p-` in parallel and automatically dispatches service-specific detailed enumeration based on discovered open ports.

### Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SMB pre-check (Gather hostname / domain)                 │
│ 2. Concurrent rustscan + nmap -p- → Discovers all TCP ports │
│ 3. nmap -sCV (Version & Script detection)                   │
│ 4. nmap --script vuln (Vulnerability scanning)              │
│ 5. nmap -sU --top-ports 20 (UDP scanning)                    │
│ 6. Automated Service-Specific Enumeration:                  │
│    SMB(445)  → nxc shares/users + enum4linux-ng             │
│    HTTP(80+) → whatweb + curl + feroxbuster + davtest + ffuf│
│    LDAP(389) → nxc ldap + ldapsearch                        │
│    FTP(21)   → nxc ftp anonymous                            │
│    SSH(22)   │ SSH Banner grab                              │
│    MSSQL(1433)→ nxc mssql + SA trial                        │
│    MySQL(3306)→ nxc mysql                                   │
│    Postgres  → nxc postgres                                 │
│    Redis(6379)→ redis-cli ping/info                         │
│    SMTP(25)  → nxc smtp                                     │
│ 7. Generate focus.html report                               │
└─────────────────────────────────────────────────────────────┘

```

### Options

| Option | Description |
| --- | --- |
| `-i IP` | Target IP address **[Required]** |
| `--ligolo` | Route through ligolo-ng TUN interface |
| `--top-ports N` | Fast mode: Scan only top N ports |
| `--web-exts EXTS` | File extensions passed to feroxbuster (e.g., `php,html,asp`) |
| `--fw` | feroxbuster filter: Word count |
| `--fl` | feroxbuster filter: Line count |
| `--fs` | feroxbuster filter: Size |
| `--no-report` | Do not generate an HTML report |

### Examples

```bash
# Basic deep dive scan
python3 proxenum.py focus -i 10.10.10.5

# Add PHP and HTML extensions to feroxbuster
python3 proxenum.py focus -i 10.10.10.5 --web-exts php,html

# Fast mode (Top 200 ports)
python3 proxenum.py focus -i 10.10.10.5 --top-ports 200

# Enumerate an ASP.NET site via ligolo
python3 proxenum.py focus -i 172.16.100.10 --ligolo --web-exts asp,aspx

```

---

## 🟣 drill Mode

Designed to scan multiple targets, evaluate them using a scoring algorithm, automatically select the highest-value hosts, and sequentially execute `focus` mode on them.

### Scoring Logic

Points are assigned to each host based on combinations of open ports:

| Port / Combination | Points | Reasoning |
| --- | --- | --- |
| MSSQL (1433) | 18 | High-value database |
| WinRM (5985/5986) | 14 | Windows Foothold |
| Redis (6379) | 14 + 8 | Often unauthenticated |
| MongoDB (27017) | 14 + 8 | Often unauthenticated |
| SMB (445) | 12 | Relay candidate / Share access |
| DC Combo (88+389+445) | Bonus +12 | Domain Controller |
| MSSQL + SMB | Bonus +10 | High-value target |
| WinRM + SMB | Bonus +6 | Complete Windows Foothold |

### Options

| Option | Description |
| --- | --- |
| `-i FILE` | Target IP list file **[Required]** |
| `--top N` | Number of high-value targets to deep dive (Default: 3) |
| `--ligolo` | Route through ligolo-ng TUN interface |
| `--top-ports N` | Fast mode: Scan only top N ports |
| `--web-exts EXTS` | File extensions passed to feroxbuster |
| `--no-report` | Do not generate an HTML report |

### Examples

```bash
# Scan all hosts, then deep dive into the top 3
python3 proxenum.py drill -i ip.txt

# Deep dive into the top 5 hosts
python3 proxenum.py drill -i ip.txt --top 5

# Fast mode + ASP.NET extensions
python3 proxenum.py drill -i ip.txt --top 3 --top-ports 200 --web-exts asp,aspx

# Via ligolo
python3 proxenum.py drill -i ip.txt --ligolo --top 5

```

---

## ⚙️ stax Mode

Static analysis and utility mode. This requires no network scanning and parses previously obtained hash files or dump outputs.

### Sub-features

| Option | Description |
| --- | --- |
| `--crack-ntlm FILE` | Crack NTLM hashes using hashcat + rockyou.txt |
| `--crack-secrets FILE` | Parse impacket secretsdump output, extract & crack NT hashes |
| `--mimi-check FILE` | Parse Mimikatz / pypykatz dumps (Extracts cleartext passwords & NTLM hashes) |
| `--winpeas-check FILE` | Extract privilege escalation indicators from WinPEAS output |
| `--linpeas-check FILE` | Extract privilege escalation indicators from LinPEAS output |
| `--merge-file FILE...` | Merge and deduplicate multiple files (Specify output with `-o`) |
| `--push-file SOURCE` | Append and deduplicate new entries from SOURCE into TARGET (`-o`) |
| `--parse-users` | Automatically collect usernames from command history logs |
| `--parse-web` | Parse feroxbuster and web enumeration outputs |
| `-o FILE` | Output target file for `--merge-file` / `--push-file` |
| `--show-logs` | List existing proxscan log files in the current directory |

### Examples

```bash
# Crack NTLM hashes
python3 proxenum.py stax --crack-ntlm ntlm_hashes.txt

# Parse secretsdump output and crack extracted hashes
python3 proxenum.py stax --crack-secrets secretsdump_output.txt

# Parse Mimikatz dumps (separates cleartext passwords and hashes)
python3 proxenum.py stax --mimi-check mimikatz.txt
# -> Automatically exports mimi_users.txt and mimi_ntlm.hash

# Analyze WinPEAS (AlwaysInstallElevated, Token Privileges, Unquoted Paths, etc.)
python3 proxenum.py stax --winpeas-check winpeas_output.txt

# Analyze LinPEAS (SUID binaries, sudo NOPASSWD, NFS no_root_squash, etc.)
python3 proxenum.py stax --linpeas-check linpeas_output.txt

# Merge and deduplicate multiple user lists
python3 proxenum.py stax --merge-file users1.txt users2.txt users3.txt -o all_users.txt

# Append new users to an existing list without duplicates
python3 proxenum.py stax --push-file new_users.txt -o all_users.txt

# View available proxscan logs
python3 proxenum.py stax --show-logs

```

#### Supported Formats for --mimi-check

| Format | Support |
| --- | --- |
| pypykatz output (`== LogonSession ==`) | ✅ |
| Classic Mimikatz (`sekurlsa::logonpasswords`) | ✅ |
| lsadump::sam (`User :` / `Hash NTLM:`) | ✅ |
| lsadump::dcsync (`SAM Username :` / `Credentials:`) | ✅ |

#### Indicators Tracked by --winpeas-check

| Category | Description / Details |
| --- | --- |
| AlwaysInstallElevated | MSI installer running with SYSTEM privileges |
| Token Privilege | SeImpersonatePrivilege, etc. (Potato exploits) |
| Unquoted Service Path | Services with spaces lacking quotation marks |
| Writable Service | Modifiable service binaries |
| Autologon | Cleartext credentials stored in registry |
| LAPS | Readable LAPS local admin passwords |
| Scheduled Task | Modifiable task execution targets |
| Stored Credential | Windows Credential Manager vaults |
| PATH Hijack | Write-accessible directories in the system PATH |
| Password in Registry | Cleartext passwords exposed in registry keys |

#### Indicators Tracked by --linpeas-check

| Category | Description / Details |
| --- | --- |
| Sudo NOPASSWD | Sudo access configured without requiring passwords |
| NFS no_root_squash | NFS mount configuration with root squash disabled |
| Writable Sensitive File | World-writable critical files like `/etc/passwd` |
| Capability | Dangerous Linux capabilities like `cap_setuid+ep` |
| Cron Writable | Scheduled cron jobs pointing to modifiable scripts |
| SSH Private Key | Exposed SSH private keys |
| SUID Binary | SUID binaries listed on GTFOBins |
| Docker/LXC Socket | Exposed container sockets allowing escapes |

---

## 📋 proxscan Scan Log Feature

The `scan` mode automatically logs details into a file named `proxscan.N.json` upon completion.

### Behavior

```
1st Execution: Creates proxscan.1.json
2nd Execution: Auto-loads proxscan.1.json → Skips port scan; proceeds to SMB enum & spray
--new-log:     Forces creation of proxscan.2.json (ignores existing logs)
--skip-log:    Completely bypasses log reading and writing

```

### Log Schema Example

```json
{
  "created": "2025-05-25T10:30:00.000000",
  "version": "1.5.0",
  "domain": "medtech.com",
  "hosts": {
    "10.10.10.5": {
      "hostname": "DC01",
      "fqdn": "dc01.medtech.com",
      "domain": "medtech.com",
      "os_info": "Windows Server 2022",
      "smb_signing": true,
      "smbv1": false,
      "open_ports": {"445": "microsoft-ds", "88": "kerberos-sec"},
      "udp_ports": {}
    }
  }
}

```

### Log Management

```bash
# View all available scan logs
python3 proxenum.py stax --show-logs

# Output Example:
# File            Created              Domain       Hosts  Version
# proxscan.1.json   2025-05-25 10:30:00  medtech.com  7      1.5.0
# proxscan.2.json   2025-05-25 14:15:00  corp.local   3      1.5.0

```

---

## 📊 HTML Reports

Scan results are cleanly outputted into interactive HTML reports.

| File Name | Generation Mode | Contents |
| --- | --- | --- |
| `scan_N.html` | scan (N = target count) | Global multi-host summary |
| `drill_N.html` | drill (N = target count) | Drill results + Individual host focus sections |
| `focus.html` | focus | Single-host in-depth analysis |

### Key Report Sections

**scan / drill Report (Sidebar Navigation)**

| Tab | Description |
| --- | --- |
| Overview | Total host, port, credential counts, and overall elapsed time |
| Critical | SMB shares found / Vulnerabilities detected / Anonymous access / User lists |
| Hosts | Table detailing IP, Hostname, FQDN, OS, Domain, and SMB Signing status |
| Ports | Port heatmaps (category color-coded) + interactive port tooltips |
| Credentials | Successfully validated credentials (with Admin privilege flagging) |
| Matrix | Credential × Host password spraying matrix |
| Priority | High-value targets ranked with medals (🥇🥈🥉) |
| Focus | Detailed service-level enumeration outputs per host (drill mode only) |
| Commands | Complete audit log of executed commands with copy buttons |
| Checklist | Auto-generated Markdown reporting checklist |
| HTTP Links | One-click hyperlinked endpoints for detected HTTP/HTTPS services |
| /etc/hosts | Pre-formatted mapping blocks for `/etc/hosts` with a copy button |

**focus Report (Single Host View)**

| Tab | Description |
| --- | --- |
| ⚠ Critical | Active SMB shares / Exploitable vulnerabilities / Users / Open access |
| TCP/UDP Ports | List of open ports (High-value ports are highlighted) |
| Vuln Scan | Parsed results from `nmap --script vuln` |
| UDP Raw | Raw output from UDP scans |
| SMB Details | Parsed `enum4linux-ng` details (users, shares, password policy) |
| HTTP | Consolidated data from feroxbuster / whatweb / curl headers |
| Command Log | Comprehensive historical log of all fired commands (with copy buttons) |

```

```
