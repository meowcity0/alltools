#!/usr/bin/env python3
"""proxenum — OSCP Recon Suite"""

import sys
import argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich import box

from core.quotes import get_random_quote
from core.models import EnumSession
from core.smb import SMBEnumerator
from core.nmap import NmapScanner
from core.spray import PasswordSprayer
from core.report import ReportGenerator
from core.stax import StaticAnalyzer
from core.heartbeat import HeartBeat
from core.enum_extra import ExtraEnumerator
from core.focus import FocusEnumerator
import core.sessiondb as sessiondb

console = Console(highlight=False)
VERSION = "2.2.0"

_MODE_COLORS = {
    "scan":   "#7aab7a",
    "focus":  "#c9a96e",
    "drill":  "#8b7aa8",
    "stax":   "#8b949e",
    "adenum": "#8b7aa8",
    "spray":  "#c9a96e",
}


def resolve_input(value: str) -> list[str]:
    p = Path(value)
    if p.is_file():
        lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]
        console.print(f"  [dim #8b949e]  {len(lines)} line(s) loaded from {value}[/dim #8b949e]")
        return lines
    return [value]


def print_banner():
    console.print()
    console.print(
        "  [bold #58a6ff]◆[/bold #58a6ff]  "
        "[bold #e6edf3]proxenum[/bold #e6edf3]  "
        "[bold #58a6ff]◆[/bold #58a6ff]"
    )
    console.print(f"  [dim #30363d]{'─' * 36}[/dim #30363d]")
    console.print(
        "  [#7aab7a]scan[/#7aab7a]  [dim #656d76]·[/dim #656d76]  "
        "[#c9a96e]focus[/#c9a96e]  [dim #656d76]·[/dim #656d76]  "
        "[#8b7aa8]drill[/#8b7aa8]  [dim #656d76]·[/dim #656d76]  "
        "[#8b949e]stax[/#8b949e]  [dim #656d76]·[/dim #656d76]  "
        "[#8b7aa8]adenum[/#8b7aa8]"
    )
    console.print(f"  [dim #656d76]v{VERSION}  ·  OSCP Recon Suite[/dim #656d76]")
    console.print()
    quote_en, quote_ja = get_random_quote()
    console.print(
        Panel(
            f"[italic #c0c8d4]{quote_en}[/italic #c0c8d4]\n[dim #8b949e]{quote_ja}[/dim #8b949e]",
            border_style="#30363d",
            box=box.SIMPLE,
            padding=(0, 2),
        )
    )
    console.print()


def print_mode_panel(mode: str, detail: str):
    color = _MODE_COLORS.get(mode, "#e6edf3")
    console.print(
        Panel(
            f"[bold {color}]{mode.upper()}[/bold {color}]"
            f"  [dim #8b949e]{detail}[/dim #8b949e]",
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


# ─────────────────────────────────────────────────────────── sessiondb helpers

def _load_db(args, session: EnumSession, target_ip: str | None = None,
             full_history: bool = False) -> bool:
    """Load proxenum.json into session. Returns True if ports were loaded."""
    if getattr(args, "skip_log", False):
        return False
    had_ports = sessiondb.load(session, target_ip=target_ip,
                               full_history=full_history)
    if had_ports or session.hosts:
        db = sessiondb.info()
        if db:
            cmd_count = sum(v.get("commands", 0) for v in db.get("host_info", {}).values())
            cmd_count += db.get("global_commands", 0)
            console.print(
                f"  [dim #8b949e]  📂 proxenum.json — "
                f"{db['host_count']} host(s) · {cmd_count} saved cmd(s) · "
                f"updated {db['updated'][:16]}[/dim #8b949e]"
            )
    return had_ports


def _save_db(args, session: EnumSession, target_ip: str | None = None,
             full_history: bool = False):
    if getattr(args, "skip_log", False):
        return
    sessiondb.save(session, VERSION, target_ip=target_ip,
                   full_history=full_history)
    console.print(f"  [dim #8b949e]  💾 proxenum.json updated[/dim #8b949e]")


# ─────────────────────────────────────────────────────────── scan

def cmd_scan(args):
    if (args.p or args.n) and not args.u:
        console.print("[red]  -u is required when -p or -n is specified.[/red]")
        sys.exit(1)

    ips = resolve_input(args.i)
    users = resolve_input(args.u) if args.u else []
    passwords = resolve_input(args.p) if args.p else []
    ntlms = resolve_input(args.n) if args.n else []

    mode_tag = " · proxy" if args.proxy else (" · ligolo" if args.ligolo else "")
    print_mode_panel("scan", f"{len(ips)} target(s){mode_tag}")

    session = EnumSession(input_ips=ips, use_proxy=args.proxy,
                          use_ligolo=args.ligolo,
                          top_ports=args.top_ports)
    hb = HeartBeat(console)
    ports_loaded = _load_db(args, session)

    hb.tick("SMB enumeration")
    SMBEnumerator(console, session, no_report=args.no_report).run(ips)
    hb.done("SMB done")

    if ports_loaded:
        console.print("  [dim #8b949e]  Port scan skipped (ports loaded from db)[/dim #8b949e]")
    elif not args.no_portscan:
        hb.tick("Nmap scanning")
        NmapScanner(console, session, no_report=args.no_report).run(ips)
        hb.done("Nmap done")
    else:
        console.print("  [dim #8b949e]  Nmap skipped (--no-portscan)[/dim #8b949e]")

    extra = None
    if not args.proxy:
        extra = ExtraEnumerator(console, session)
        extra.run_anon(users)

    if users and (passwords or ntlms):
        hb.tick("Password spray")
        PasswordSprayer(console, session, no_report=args.no_report).run(
            ips, users, passwords, ntlms=ntlms,
            no_brute=args.no_brute,
            continue_on_success=args.continue_on_success,
        )
        hb.done("Spray done")

    if extra is not None:
        extra.run_auth()

    hb.summary()
    _save_db(args, session)

    if not args.no_report:
        ReportGenerator(console, session, mode="scan").generate()


# ─────────────────────────────────────────────────────────── focus

def cmd_focus(args):
    ip = args.i
    ligolo = getattr(args, "ligolo", False)
    tag = " · ligolo" if ligolo else ""
    print_mode_panel("focus", f"Target: {ip}{tag}")

    session = EnumSession(input_ips=[ip], use_proxy=False, use_ligolo=ligolo,
                          top_ports=getattr(args, "top_ports", 0),
                          web_exts=getattr(args, "web_exts", ""),
                          web_filter_words=getattr(args, "fw", 0),
                          web_filter_lines=getattr(args, "fl", 0),
                          web_filter_size=getattr(args, "fs", 0),
                          web_recurse=getattr(args, "recurse", False))

    # Load accumulated data (ports, creds, prior scan results) from shared db
    _load_db(args, session, target_ip=ip)

    hb = HeartBeat(console)
    hb.tick("SMB pre-check")
    SMBEnumerator(console, session, no_report=args.no_report).run([ip])
    hb.done("SMB done")

    fe = FocusEnumerator(console, session, ip, no_report=args.no_report)
    fe.run()

    hb.summary()
    _save_db(args, session, target_ip=ip)

    if not args.no_report:
        from core.report import FocusReport
        FocusReport(console, session, ip).generate()


# ─────────────────────────────────────────────────────────── drill

def cmd_drill(args):
    ips = resolve_input(args.i)
    ligolo = getattr(args, "ligolo", False)
    tag = " · ligolo" if ligolo else ""
    print_mode_panel("drill", f"{len(ips)} targets → auto-focus top {args.top}{tag}")

    top_ports = getattr(args, "top_ports", 0)
    web_exts = getattr(args, "web_exts", "")
    web_recurse = getattr(args, "recurse", False)
    session = EnumSession(input_ips=ips, use_proxy=False, use_ligolo=ligolo,
                          top_ports=top_ports)
    hb = HeartBeat(console)
    ports_loaded = _load_db(args, session)

    hb.tick("SMB enumeration")
    SMBEnumerator(console, session).run(ips)
    hb.done("SMB done")

    if ports_loaded:
        console.print("  [dim #8b949e]  Port scan skipped (ports loaded from db)[/dim #8b949e]")
    else:
        hb.tick("Nmap scanning")
        NmapScanner(console, session).run(ips)
        hb.done("Nmap done")
        _save_db(args, session)

    from core.scoring import rank_hosts, score_host_final
    ranked = rank_hosts(session)
    top_n = min(args.top, len(ranked))

    console.print(f"\n  [bold #c9a96e]⚡ Top {top_n} focus target(s):[/bold #c9a96e]")
    for i, (ip, host, score, reasons) in enumerate(ranked[:top_n], 1):
        medals = ["🥇", "🥈", "🥉"]
        m = medals[i - 1] if i <= 3 else f"#{i}"
        r = ", ".join(reasons[:2]) or "—"
        console.print(f"  [dim]  {m} {ip} ({host.display_name}) — {score} pts — {r}[/dim]")
    console.print()

    focus_data: dict[str, EnumSession] = {}

    def _write_overall(quiet: bool):
        """Render the consolidated drill.html. Wrapped so a single bad host's
        data can never abort the run or silently lose the whole report."""
        if args.no_report:
            return
        try:
            ReportGenerator(console, session, focus_data=focus_data,
                            mode="drill").generate(quiet=quiet)
        except Exception as e:
            console.print(f"  [bold #f85149]  ⚠ overall report failed: {e}[/bold #f85149]")

    for ip, host, score, reasons in ranked[:top_n]:
        fsession = EnumSession(input_ips=[ip], use_proxy=False, use_ligolo=ligolo,
                               top_ports=top_ports, web_exts=web_exts,
                               web_filter_words=getattr(args, "fw", 0),
                               web_filter_lines=getattr(args, "fl", 0),
                               web_filter_size=getattr(args, "fs", 0),
                               web_recurse=web_recurse)
        fsession.hosts[ip] = host
        fsession.domain = session.domain
        h0 = fsession.hosts.get(ip)
        disp0 = (h0.display_name if h0 and h0.display_name != ip
                 else ip.replace(".", "_"))
        fe = FocusEnumerator(console, fsession, ip, no_report=args.no_report)
        # Per-host progressive report → {disp}/report.html (no cross-host clobber)
        fe.report_dir = disp0
        fe.report_name = "report.html"
        fe.run()
        focus_data[ip] = fsession
        _save_db(args, fsession, target_ip=ip)  # persist focus results per-host

        if not args.no_report:
            try:
                from core.report import FocusReport
                FocusReport(console, fsession, ip).generate(
                    output_dir=disp0, filename="report.html", quiet=True
                )
            except Exception as e:
                console.print(f"  [bold #f85149]  ⚠ {disp0}/report.html failed: {e}[/bold #f85149]")
        # Refresh the consolidated report after every host so it exists early
        # and survives an interrupted run (no waiting until the very end).
        _write_overall(quiet=True)
        if not args.no_report:
            console.print(f"  [dim #656d76]  📄 drill.html updated ({len(focus_data)}/{top_n})[/dim #656d76]")

    # Final ranking after focus — uses accumulated findings
    console.print(f"\n  [bold #c9a96e]🏆 Final Attack Surface Ranking (post-focus):[/bold #c9a96e]")
    final_ranked = []
    for ip, fsession in focus_data.items():
        host = fsession.hosts.get(ip)
        s, r = score_host_final(host, fsession)
        final_ranked.append((ip, host, s, r))
    final_ranked.sort(key=lambda x: x[2], reverse=True)
    medals = ["🥇", "🥈", "🥉"]
    for i, (ip, host, score, reasons) in enumerate(final_ranked, 1):
        m = medals[i - 1] if i <= 3 else f"#{i}"
        name = host.display_name if host else ip
        r = ", ".join(reasons[:3]) or "—"
        console.print(f"  [bold]  {m} {ip} ({name}) — {score} pts[/bold]")
        console.print(f"       [dim #8b949e]{r}[/dim #8b949e]")
    console.print()

    hb.summary()

    _write_overall(quiet=False)


# ─────────────────────────────────────────────────────────── stax

def cmd_stax(args):
    print_mode_panel("stax", "static analysis")
    analyzer = StaticAnalyzer(console)

    did_something = False
    if args.crack_ntlm:
        analyzer.crack_ntlm(args.crack_ntlm)
        did_something = True
    if args.mimi_check:
        analyzer.parse_mimikatz(args.mimi_check)
        did_something = True
    if args.crack_secrets:
        analyzer.crack_secrets(args.crack_secrets)
        did_something = True
    if args.merge_file:
        analyzer.merge_files(args.merge_file, args.output or "merged.txt")
        did_something = True
    if args.push_file:
        if not args.output:
            console.print("[red]  --push-file requires -o TARGET[/red]")
            sys.exit(1)
        analyzer.push_file(args.push_file, args.output)
        did_something = True
    if args.show_logs:
        _show_session_info()
        did_something = True
    if getattr(args, "winpeas_check", None):
        analyzer.parse_winpeas(args.winpeas_check)
        did_something = True
    if getattr(args, "linpeas_check", None):
        analyzer.parse_linpeas(args.linpeas_check)
        did_something = True
    if getattr(args, "parse_users", None):
        analyzer.parse_net_users(args.parse_users, args.output or "users.txt")
        did_something = True
    if getattr(args, "parse_web", None):
        analyzer.parse_web_log(args.parse_web, args.output or None)
        did_something = True
    if getattr(args, "parse_privesc", None):
        from core.privesc import PrivEscAnalyzer
        pa = PrivEscAnalyzer()
        out = args.output or "privesc.html"
        console.rule("[bold #f85149]  PrivEsc Report  ", style="#30363d")
        findings = pa.analyze_files(args.parse_privesc)
        stats = {s: sum(1 for f in findings if f.severity == s)
                 for s in ("critical", "high", "medium", "info")}
        console.print(
            f"\n  [bold #f85149]🔴 {stats['critical']} critical[/bold #f85149]  "
            f"[#f0883e]🟠 {stats['high']} high[/#f0883e]  "
            f"[#d29922]🟡 {stats['medium']} medium[/#d29922]  "
            f"({len(findings)} total findings)\n"
        )
        for f in findings:
            col = {"critical": "#f85149", "high": "#f0883e", "medium": "#d29922"}.get(f.severity, "#8b949e")
            console.print(f"  [{col}]{f.severity:8s}[/{col}]  [#c9a96e]{f.category:<28s}[/#c9a96e]  {f.title}")
        pa.generate_html(findings, args.parse_privesc, out)
        console.print(f"\n  [bold #7aab7a]✓ HTML report → {out}[/bold #7aab7a]\n")
        did_something = True
    if not did_something:
        console.print("[dim #8b949e]  No stax option specified. Try --help.[/dim #8b949e]")


def _show_session_info():
    from rich.table import Table
    from rich import box as rbox
    db = sessiondb.info()
    if not db:
        console.print("  [dim]  No proxenum.json found in current directory.[/dim]")
        return
    t = Table(box=rbox.SIMPLE_HEAD, border_style="#30363d",
               header_style="bold #c9a96e", show_edge=False, padding=(0, 1))
    t.add_column("Field", style="#c0c8d4")
    t.add_column("Value", style="#8b949e")
    t.add_row("File", str(db["path"]))
    t.add_row("Created", db["created"][:19])
    t.add_row("Updated", db["updated"][:19])
    t.add_row("Domain", db["domain"])
    t.add_row("Hosts", str(db["host_count"]))
    t.add_row("Credentials", str(db["cred_count"]))
    t.add_row("Version", db["version"])
    console.print(t)


# ─────────────────────────────────────────────────────────── adenum

def cmd_adenum(args):
    from core.adenum import ADEnumerator

    ips: list[str] = []
    for val in args.i:
        ips.extend(resolve_input(val))
    if not ips:
        console.print("[red]  No target IPs specified.[/red]")
        sys.exit(1)

    usernames = resolve_input(args.u) if args.u else []
    passwords = resolve_input(args.p) if args.p else []
    ntlm_arg = getattr(args, "H", None)
    ntlms = resolve_input(ntlm_arg) if ntlm_arg else []

    tag_parts: list[str] = []
    if args.d:
        tag_parts.append(f"domain:{args.d}")
    if usernames:
        tag_parts.append(f"{len(usernames)} user(s)")
    if passwords:
        tag_parts.append(f"{len(passwords)} pass(es)")
    if ntlms:
        tag_parts.append(f"{len(ntlms)} hash(es)")
    tag = " · " + " · ".join(tag_parts) if tag_parts else ""

    print_mode_panel("adenum", f"{len(ips)} target(s){tag}")

    session = EnumSession(input_ips=ips)
    # full_history: restore adenum's prior command log so a 2nd run skips
    # completed port scans / sprays / roasting instead of repeating them.
    _load_db(args, session, full_history=True)

    enumerator = ADEnumerator(
        console=console,
        session=session,
        ips=ips,
        usernames=usernames,
        passwords=passwords,
        ntlms=ntlms,
        dc_ip=getattr(args, "dc", None) or None,
        domain=args.d or None,
        no_report=args.no_report,
        no_brute=getattr(args, "no_brute", False),
        continue_on_success=getattr(args, "continue_on_success", False),
        local_auth=getattr(args, "local_auth", False),
        do_hydra=getattr(args, "brute", False),
        top_ports=getattr(args, "top_ports", 0),
        from_json=getattr(args, "from_json", False),
        persist=not getattr(args, "skip_log", False),
    )
    enumerator.run()

    _save_db(args, session, full_history=True)

    if not args.no_report:
        from core.report import ADReport
        ADReport(console, session, enumerator).generate()


# ─────────────────────────────────────────────────────────── spray

def cmd_spray(args):
    from core.sprayenum import SprayEnumerator

    ips: list[str] = []
    for val in (args.i or []):
        ips.extend(resolve_input(val))

    usernames = resolve_input(args.u) if args.u else []
    passwords = resolve_input(args.p) if args.p else []
    ntlms = resolve_input(args.H) if getattr(args, "H", None) else []

    session = EnumSession(input_ips=ips)
    _load_db(args, session, full_history=True)

    # -i omitted → spray every host already in proxenum.json
    if not ips:
        ips = sorted(session.hosts.keys())
        if ips:
            console.print(f"  [dim #8b949e]  Using {len(ips)} host(s) from proxenum.json[/dim #8b949e]")
    if not ips:
        console.print("[red]  No targets: pass -i or run a scan first so proxenum.json has hosts.[/red]")
        sys.exit(1)
    session.input_ips = ips

    tag_parts = []
    if usernames: tag_parts.append(f"{len(usernames)} user(s)")
    if passwords: tag_parts.append(f"{len(passwords)} pass(es)")
    if ntlms: tag_parts.append(f"{len(ntlms)} hash(es)")
    tag = " · " + " · ".join(tag_parts) if tag_parts else " · creds from json"
    print_mode_panel("spray", f"{len(ips)} target(s){tag}")

    sprayer = SprayEnumerator(
        console=console, session=session, ips=ips,
        usernames=usernames, passwords=passwords, ntlms=ntlms,
        domain=args.d or None,
        local_auth=getattr(args, "local_auth", False),
        no_brute=getattr(args, "no_brute", False),
        persist=not getattr(args, "skip_log", False),
    )
    sprayer.run()
    _save_db(args, session, full_history=True)

    if not args.no_report:
        from core.report import SprayReport
        SprayReport(console, session, sprayer).generate()


# ─────────────────────────────────────────────────────────── argparse

def _scan_parser(sub, name: str, help_text: str):
    ep = sub.add_parser(name, help=help_text)
    ep.add_argument("-i", required=True, metavar="IP/FILE",
                    help="Target IP(s) — file path or direct value")
    ep.add_argument("-u", metavar="USER/FILE",
                    help="Username(s)")
    ep.add_argument("-p", metavar="PASS/FILE",
                    help="Password(s) (requires -u)")
    ep.add_argument("-n", metavar="HASH/FILE",
                    help="NTLM hash(es) (requires -u)")
    ep.add_argument("--no-brute", action="store_true",
                    help="nxc --no-brute (1:1 user:pass pairing)")
    ep.add_argument("--continue-on-success", action="store_true",
                    help="Keep spraying after first success")
    ep.add_argument("--no-report", action="store_true",
                    help="CLI output only, skip HTML report")
    ep.add_argument("--no-portscan", action="store_true",
                    help="Skip port scanning")
    ep.add_argument("--proxy", action="store_true",
                    help="Route through proxychains4 -q (SOCKS pivot)")
    ep.add_argument("--ligolo", action="store_true",
                    help="ligolo-ng tunnel mode (TUN interface, conservative timing)")
    ep.add_argument("--top-ports", type=int, default=0, metavar="N",
                    help="Fast mode: scan only top N ports (skip rustscan + -p-)")
    ep.add_argument("--skip-log", action="store_true",
                    help="Do not read or write proxenum.json session db")
    return ep


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxenum",
        description="OSCP Recon Suite — scan · focus · drill · stax",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"proxenum {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # scan
    sp = _scan_parser(sub, "scan", "Multi-host scan: SMB + Nmap + spray + extra enum")
    sp.set_defaults(func=cmd_scan)

    # focus (single-IP deep dive)
    fp = sub.add_parser("focus", help="Deep enumeration of a single IP")
    fp.add_argument("-i", required=True, metavar="IP", help="Target IP address")
    fp.add_argument("--no-report", action="store_true", help="Skip HTML report")
    fp.add_argument("--ligolo", action="store_true",
                    help="ligolo-ng tunnel mode (conservative timing)")
    fp.add_argument("--top-ports", type=int, default=0, metavar="N",
                    help="Fast mode: scan only top N ports")
    fp.add_argument("--web-exts", default="", metavar="EXTS",
                    help="File extensions for feroxbuster (e.g. php,html,asp)")
    fp.add_argument("--fw", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-words N")
    fp.add_argument("--fl", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-lines N")
    fp.add_argument("--fs", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-size N")
    fp.add_argument("--recurse", action="store_true",
                    help="Enable feroxbuster recursive directory scanning (slower)")
    fp.add_argument("--skip-log", action="store_true",
                    help="Do not read or write proxenum.json session db")
    fp.set_defaults(func=cmd_focus)

    # drill (auto scan + focus top N)
    dp = sub.add_parser("drill", help="Scan targets then auto-focus on top N")
    dp.add_argument("-i", required=True, metavar="FILE", help="Target IP list file")
    dp.add_argument("--top", type=int, default=3, metavar="N",
                    help="Number of top targets to deep-dive (default: 3)")
    dp.add_argument("--no-report", action="store_true", help="Skip HTML reports")
    dp.add_argument("--ligolo", action="store_true",
                    help="ligolo-ng tunnel mode (conservative timing)")
    dp.add_argument("--top-ports", type=int, default=0, metavar="N",
                    help="Fast mode: scan only top N ports")
    dp.add_argument("--web-exts", default="", metavar="EXTS",
                    help="File extensions for feroxbuster (e.g. php,html,asp)")
    dp.add_argument("--fw", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-words N")
    dp.add_argument("--fl", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-lines N")
    dp.add_argument("--fs", type=int, default=0, metavar="N",
                    help="feroxbuster --filter-size N")
    dp.add_argument("--recurse", action="store_true",
                    help="Enable feroxbuster recursive directory scanning (slower)")
    dp.add_argument("--skip-log", action="store_true",
                    help="Ignore existing session db, run fresh port scan")
    dp.set_defaults(func=cmd_drill)

    # adenum — Active Directory enumeration
    adp = sub.add_parser(
        "adenum",
        help="Active Directory enumeration: user enum, AS-REP, Kerberoast, BloodHound",
    )
    adp.add_argument("-i", required=True, nargs="+", metavar="IP",
                     help="Target IP(s) — space-separated, or file path(s)")
    adp.add_argument("-u", metavar="USER/FILE",
                     help="Username(s) or file — single value or path to users.txt")
    adp.add_argument("-p", metavar="PASS/FILE",
                     help="Password(s) or file — single value or path to passwords.txt")
    adp.add_argument("-H", metavar="NTLM/FILE",
                     help="NTLM hash(es) or file for Pass-the-Hash — single or path to ntlm.hash")
    adp.add_argument("-d", metavar="DOMAIN",
                     help="Domain name (auto-detected from session data if omitted)")
    adp.add_argument("--dc", metavar="IP",
                     help="Domain Controller IP override (auto-detected from -i list by default)")
    adp.add_argument("--no-brute", action="store_true",
                     help="nxc --no-brute: pair users 1:1 with passwords instead of all combinations")
    adp.add_argument("--continue-on-success", action="store_true",
                     help="Keep spraying after first successful credential")
    adp.add_argument("--local-auth", action="store_true",
                     help="Also spray with --local-auth (local account testing in addition to domain)")
    adp.add_argument("--brute", action="store_true",
                     help="Enable Hydra brute-force against FTP/SSH on open ports")
    adp.add_argument("--top-ports", type=int, default=0, metavar="N",
                     help="Limit port scan to top N ports (default: top 1000)")
    adp.add_argument("--from-json", action="store_true",
                     help="Fast per-user enum: reuse ports + valid creds from "
                          "proxenum.json, skip port discovery and spray entirely")
    adp.add_argument("--no-report", action="store_true",
                     help="CLI output only, skip adenum.html report")
    adp.add_argument("--skip-log", action="store_true",
                     help="Do not read or write proxenum.json session db")
    adp.set_defaults(func=cmd_adenum)

    # spray — credentialed service sweep (uses proxenum.json ports + creds)
    spp = sub.add_parser(
        "spray",
        help="Credentialed sweep of easily-missed services (ssh/mssql/mysql/webdav…) "
             "using proxenum.json ports + valid creds; loot under spray/<user>/",
    )
    spp.add_argument("-i", nargs="+", metavar="IP",
                     help="Target IP(s) — space-separated or file(s). Omit to use all hosts in proxenum.json")
    spp.add_argument("-u", metavar="USER/FILE", help="Username(s) or file")
    spp.add_argument("-p", metavar="PASS/FILE", help="Password(s) or file")
    spp.add_argument("-H", metavar="NTLM/FILE", help="NTLM hash(es) or file (PTH)")
    spp.add_argument("-d", metavar="DOMAIN", help="Domain (auto-detected if omitted)")
    spp.add_argument("--no-brute", action="store_true",
                     help="Pair users 1:1 with passwords instead of all combinations")
    spp.add_argument("--local-auth", action="store_true",
                     help="Use --local-auth for nxc checks")
    spp.add_argument("--no-report", action="store_true",
                     help="CLI output only, skip spray.html report")
    spp.add_argument("--skip-log", action="store_true",
                     help="Do not read or write proxenum.json session db")
    spp.set_defaults(func=cmd_spray)

    # stax
    stp = sub.add_parser("stax", help="Static analysis: NTLM cracking, file merge, log view")
    stp.add_argument("--crack-ntlm", metavar="FILE",
                     help="Crack NTLM hashes with hashcat (rockyou)")
    stp.add_argument("--crack-secrets", metavar="FILE",
                     help="Parse impacket secretsdump output, extract & crack NT hashes")
    stp.add_argument("--mimi-check", metavar="FILE",
                     help="Parse Mimikatz/pypykatz dump")
    stp.add_argument("--merge-file", nargs="+", metavar="FILE",
                     help="Merge word/hash files into one, dedup (use -o for output name)")
    stp.add_argument("--push-file", metavar="SOURCE",
                     help="Push new entries from SOURCE into TARGET (-o), dedup in place")
    stp.add_argument("-o", "--output", metavar="FILE",
                     help="Output file for --merge-file / --push-file")
    stp.add_argument("--show-logs", action="store_true",
                     help="Show proxenum.json session db summary")
    stp.add_argument("--winpeas-check", metavar="FILE",
                     help="Parse WinPEAS output and extract privesc findings")
    stp.add_argument("--linpeas-check", metavar="FILE",
                     help="Parse LinPEAS output and extract privesc findings")
    stp.add_argument("--parse-users", metavar="FILE",
                     help="Parse 'net user /domain' output → clean user list (-o for output file)")
    stp.add_argument("--parse-web", metavar="FILE",
                     help="Parse feroxbuster/gobuster log → directory tree (-o for output file)")
    stp.add_argument("--parse-privesc", nargs="+", metavar="FILE",
                     help="Parse LinPEAS/WinPEAS/PowerUp log(s) → HTML privesc report (-o for output file, default: privesc.html)")
    stp.set_defaults(func=cmd_stax)

    return parser


# ─────────────────────────────────────────────────────────── main

def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
