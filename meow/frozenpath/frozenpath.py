# /// script
# dependencies = ["neo4j", "rich", "prompt_toolkit"]
# ///

import re
import logging
import sys
from neo4j import GraphDatabase
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory

logging.getLogger("neo4j").setLevel(logging.ERROR)

C_FROST  = "bold #E1F5FE"
C_ICE    = "bold #81D4FA"
C_DEEP   = "bold #01579B"
C_GLOW   = "bold #18FFFF"
C_ANOMALY = "bold #FF00FF"
C_DANGER = "bold #FF1744"
C_PRIV   = "bold #AA00FF"
C_GOLD   = "bold #FFD700"
C_LAPS   = "bold #FFF176"
C_OK     = "bold #00E676"
C_WARN   = "bold #FFAB40"

PRIV_GROUPS = [
    "BACKUP OPERATORS", "SERVER OPERATORS", "ACCOUNT OPERATORS",
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "PRINT OPERATORS",
    "SCHEMA ADMINS", "DNSADMINS", "EXCHANGE WINDOWS PERMISSIONS",
    "GROUP POLICY CREATOR OWNERS", "ORGANIZATION MANAGEMENT",
]

STANDARD_OBJECTS = {
    "ADMINISTRATOR","GUEST","KRBTGT","DOMAIN ADMINS","ENTERPRISE ADMINS",
    "SCHEMA ADMINS","DOMAIN USERS","DOMAIN GUESTS","DOMAIN COMPUTERS",
    "DOMAIN CONTROLLERS","CERT PUBLISHERS","EVERYONE","AUTHENTICATED USERS",
    "REPLICATOR","GROUP POLICY CREATOR OWNERS","READ-ONLY DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS","DENIED RODC PASSWORD REPLICATION",
    "ALLOWED RODC PASSWORD REPLICATION","KEY ADMINS","ENTERPRISE KEY ADMINS",
    "DEFAULT DOMAIN POLICY","DEFAULT DOMAIN CONTROLLERS POLICY",
    "ACCOUNT OPERATORS","SERVER OPERATORS","PRINT OPERATORS","BACKUP OPERATORS",
}

REL_COLORS = {
    "GenericAll":"bold #FF1744","WriteDacl":"bold #F50057","WriteOwner":"bold #D500F9",
    "GenericWrite":"bold #FF9100","Owns":"bold #FF5252","ReadLAPSPassword":"bold #FFF176",
    "ReadGMSAPassword":"bold #00E676","DCSync":"bold #FF1744","GetChanges":"bold #FF1744",
    "GetChangesAll":"bold #FF1744","GetChangesInFilteredSet":"bold #FF1744",
    "MemberOf":"bold #81D4FA","HasSession":"bold #18FFFF","AdminTo":"bold #FF5252",
    "AllowedToDelegate":"bold #7C4DFF","AllowedToAct":"bold #7C4DFF",
    "CanPSRemote":"bold #00E676","CanRDP":"bold #40C4FF","ExecuteDCOM":"bold #B2FF59",
    "AllExtendedRights":"bold #FF80AB","ForceChangePassword":"bold #FF4081",
    "AddMember":"bold #40C4FF","AddKeyCredentialLink":"bold #EA80FC",
    "HasSIDHistory":"bold #FF6D00","SQLAdmin":"bold #FF6D00",
}

# High-value targets: automatically discovered from the graph
# (name pattern, node label)
HV_TARGETS_PATTERNS = [
    ("(?i).*DOMAIN ADMINS.*",    "Group"),
    ("(?i).*ENTERPRISE ADMINS.*","Group"),
    ("(?i).*BACKUP OPERATORS.*", "Group"),
    ("(?i).*SERVER OPERATORS.*", "Group"),
    ("(?i).*ACCOUNT OPERATORS.*","Group"),
    ("(?i).*DNSADMINS.*",        "Group"),
    ("(?i).*SCHEMA ADMINS.*",    "Group"),
]

# Change This

URI, USER_DB, PW = "bolt://localhost:7687", "neo4j", "neo4j"

console = Console()


class FrozenPath:
    def __init__(self):
        try:
            self.driver = GraphDatabase.driver(URI, auth=(USER_DB, PW))
            with self.driver.session() as s:
                s.run("RETURN 1")
        except Exception as e:
            console.print(f"[{C_DANGER}][!] Neo4j Connection Failed: {e}[/]")
            sys.exit(1)

        self.session_prompt = PromptSession(history=InMemoryHistory())
        self.current_user: str | None = None
        self.owned_nodes: set = set()

        self.presets = {
            "roast":       "MATCH (u:User {dontreqpreauth:true}) WHERE u.enabled=true RETURN u.name",
            "kerberoast":  "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u.name, u.serviceprincipalnames",
            "laps":        "MATCH (c:Computer) WHERE c.haslaps=true RETURN c.name, c.operatingsystem",
            "dcsync":      ("MATCH (n:Base)-[:GetChangesAll]->(d:Domain) "
                            "WHERE NOT n.name=~'(?i).*(DOMAIN CONTROLLERS|ENTERPRISE DOMAIN CONTROLLERS).*' "
                            "RETURN DISTINCT n.name, labels(n)[0], d.name"),
            "ls-admin":    ("MATCH (g:Group) WHERE g.name=~'(?i).*DOMAIN ADMINS.*' "
                            "MATCH (u:User)-[:MemberOf*1..3]->(g) RETURN DISTINCT u.name"),
            "description": ("MATCH (n:Base) WHERE n.description IS NOT NULL AND n.description<>'' "
                            "RETURN n.name, labels(n)[0], n.description ORDER BY n.description"),
            "priv-users":  ("MATCH (u:User)-[:MemberOf*1..]->(g:Group) "
                            f"WHERE any(p in {PRIV_GROUPS} WHERE toUpper(g.name) CONTAINS p) "
                            "RETURN DISTINCT u.name, g.name ORDER BY g.name"),
            "ls-sessions": "MATCH (u:User)-[:HasSession]->(c:Computer) RETURN u.name, c.name ORDER BY c.name",
        }

    # ── helpers ────────────────────────────────────────────────────────────

    def _q1(self, session, q):
        try:
            return session.run(q).single()
        except Exception:
            return None

    def _qa(self, session, q):
        try:
            return list(session.run(q))
        except Exception:
            return []

    def is_anomalous(self, name):
        if not name:
            return False
        return name.split("@")[0].upper() not in STANDARD_OBJECTS

    def fmt(self, name):
        if not name:
            return f"[{C_FROST}](null)[/]"
        if name.upper().split("@")[0] in {n.upper().split("@")[0] for n in self.owned_nodes}:
            return f"[{C_OK}]✔ {name}[/]"
        if self.is_anomalous(name):
            return f"[{C_ANOMALY}]✨ {name}[/]"
        return f"[{C_FROST}]{name}[/]"

    def _s(self, v):
        return str(v) if v is not None else "?"

    # ── high-value target discovery ────────────────────────────────────────

    def _get_hv_targets(self, session):
        """
        Return list of (display_name, cypher_match_clause) for all high-value
        targets found in this specific graph.
        """
        targets = []

        # Privileged groups
        for pattern, label in HV_TARGETS_PATTERNS:
            rows = self._qa(session, f"MATCH (t:{label}) WHERE t.name=~'{pattern}' RETURN t.name AS name")
            for r in rows:
                targets.append((r["name"], r["name"]))

        # DC computers (by highvalue flag or name heuristic)
        dc_rows = self._qa(session,
            "MATCH (c:Computer) WHERE c.highvalue=true OR c.name=~'(?i).*DC.*' "
            "RETURN c.name AS name LIMIT 5")
        for r in dc_rows:
            targets.append((r["name"], r["name"]))

        return targets  # list of (display_name, exact_name_for_query)

    # ── startup intel ──────────────────────────────────────────────────────

    def quick_intel(self):
        """Fast counts only — no traversal. Returns immediately."""
        with self.driver.session() as session:
            n    = self._q1(session, "MATCH (n) RETURN count(n) as c")
            r    = self._q1(session, "MATCH ()-[r]->() RETURN count(r) as c")
            usr  = self._q1(session, "MATCH (u:User) RETURN count(u) as c")
            cmp  = self._q1(session, "MATCH (c:Computer) RETURN count(c) as c")
            dom  = self._q1(session, "MATCH (d:Domain) RETURN d.name as name LIMIT 1")
            kerb = self._q1(session, "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN count(u) as c")
            asrp = self._q1(session, "MATCH (u:User {dontreqpreauth:true}) WHERE u.enabled=true RETURN count(u) as c")
            desc = self._q1(session, """
                MATCH (n:Base) WHERE n.description IS NOT NULL
                  AND (toLower(n.description) CONTAINS 'pass'
                    OR toLower(n.description) CONTAINS 'pwd'
                    OR toLower(n.description) CONTAINS 'cred')
                RETURN count(n) as c""")
            dcs  = self._q1(session, """
                MATCH (n:Base)-[:GetChangesAll]->(d:Domain)
                WHERE NOT n.name=~'(?i).*(DOMAIN CONTROLLERS|ENTERPRISE DOMAIN CONTROLLERS).*'
                RETURN count(DISTINCT n) as c""")

            def flag(val, c=C_WARN):
                v = str(val) if val is not None else "0"
                return f"[{c}]{v}[/]" if (v.isdigit() and int(v) > 0) else f"[dim]{v}[/]"

            t = Table(border_style=C_DEEP, show_header=False, expand=True, padding=(0,1))
            t.add_column("k", style=C_ICE,  no_wrap=True)
            t.add_column("v", no_wrap=True)
            t.add_column("k2", style=C_ICE, no_wrap=True)
            t.add_column("v2", no_wrap=True)
            t.add_row("Domain",  dom["name"] if dom else "?",
                      "Nodes/Rels", f"{n['c'] if n else '?'} / {r['c'] if r else '?'}")
            t.add_row("Users",   self._s(usr["c"] if usr else None),
                      "Computers", self._s(cmp["c"] if cmp else None))
            t.add_row("🎫 Kerberoast", flag(kerb["c"] if kerb else 0),
                      "🍖 AS-REP",     flag(asrp["c"] if asrp else 0))
            t.add_row("🔑 Pass/Desc",  flag(desc["c"] if desc else 0, C_LAPS),
                      "💀 DCSync",     flag(dcs["c"]  if dcs  else 0, C_DANGER))
            console.print(Panel(t, title=f"[{C_ICE}]❄️ Environment[/]", border_style=C_DEEP))

    # ── whoami ─────────────────────────────────────────────────────────────

    def run_whoami(self, name):
        q = f"""
        MATCH (u:Base) WHERE u.name=~'(?i).*{re.escape(name)}.*'
        OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
        RETURN u.name AS name, labels(u)[0] AS type,
               collect(DISTINCT g.name) AS groups,
               u.description AS desc, u.info AS info,
               u.enabled AS enabled, u.admincount AS admincount
        LIMIT 1"""
        with self.driver.session() as session:
            res = self._q1(session, q)
            if not res:
                console.print(f"[{C_DANGER}][!] '{name}' not found.[/]")
                return
            self.current_user = res["name"]
            uname = res["name"]
            is_priv = any(pg in str(res["groups"]).upper() for pg in PRIV_GROUPS)
            groups  = [g for g in (res["groups"] or []) if g]

            lines = []
            en = "" if res["enabled"] is not False else f" [{C_DANGER}](DISABLED)[/]"
            lines.append(f"[{C_ICE}]Type:[/]   {res['type']}{en}")
            lines.append(f"[{C_ICE}]Groups:[/] {', '.join(groups) if groups else 'None'}")
            if res["admincount"]:
                lines.append(f"[{C_DANGER}]adminCount=1[/]  (was in privileged group)")
            if res["desc"]:
                lines.append(f"[{C_LAPS}]Desc:[/]   {res['desc']}")
            if res["info"]:
                lines.append(f"[{C_LAPS}]Info:[/]   {res['info']}")

            # Privilege checks (direct edges only — fast)
            checks = [
                ("ReadLAPSPassword|AllExtendedRights", "Computer", "c", "c.haslaps=true",
                 C_LAPS, "🔑 LAPS READ"),
                ("ReadGMSAPassword",      "User",     "g", None, C_OK,     "🔒 GMSA READ"),
                ("AddKeyCredentialLink",  "Base",     "t", None, C_PRIV,   "👻 SHADOW CRED"),
                ("ForceChangePassword",   "User",     "t", None, C_DANGER, "🔓 FORCE CHANGE PWD"),
                ("GenericAll|WriteDacl|WriteOwner|Owns","Base","t",None,C_DANGER,"⚡ POWERFUL ACL ON"),
                ("AdminTo|CanPSRemote|CanRDP","Computer","c",None,C_GOLD,  "👑 DIRECT ADMIN"),
                ("DCSync|GetChangesAll",  "Domain",   "d", None, C_DANGER, "💀 DCSYNC ON"),
            ]
            for edges, lbl_type, alias, extra_where, color, label in checks:
                where = f"AND {extra_where}" if extra_where else ""
                cq = f"""
                MATCH (u:Base) WHERE u.name='{uname}'
                MATCH (u)-[r:{edges}]->({alias}:{lbl_type})
                WHERE 1=1 {where}
                RETURN DISTINCT {alias}.name AS val, type(r) AS rel LIMIT 8"""
                rows = self._qa(session, cq)
                if rows:
                    parts = [f"{r['rel']}→{r['val']}" for r in rows if r["val"]]
                    lines.append(f"[{color}]{label}:[/] {', '.join(parts)}")

            if uname in self.owned_nodes:
                lines.append(f"[{C_OK}]✔ MARKED AS OWNED[/]")

            console.print(Panel(
                "\n".join(lines),
                title=f"[{C_FROST}]💎 {uname}[/]",
                border_style=C_DANGER if is_priv else C_DEEP,
                expand=False
            ))

    # ── scout / hunt ───────────────────────────────────────────────────────

    def run_scout(self, name):
        q = f"""
        MATCH (u:Base) WHERE u.name=~'(?i).*{re.escape(name)}.*'
        MATCH (u)-[r]->(t:Base)
        WHERE NOT type(r) IN ['Contains','GPLink']
        RETURN type(r) AS rel, t.name AS target, labels(t)[0] AS type, t.enabled AS en
        ORDER BY type(r), t.name"""
        with self.driver.session() as session:
            rows = self._qa(session, q)
        if not rows:
            console.print(f"[{C_DANGER}][!] No outbound edges for '{name}'[/]")
            return
        t = Table(title=f"[{C_GLOW}]📡 Scout: {name}[/]", border_style=C_DEEP)
        t.add_column("Relationship", style="bold yellow", no_wrap=True)
        t.add_column("Target")
        t.add_column("Type", style="dim")
        t.add_column("En", justify="center")
        for r in rows:
            col = REL_COLORS.get(r["rel"], C_FROST)
            en  = "✅" if r["en"] else ("❌" if r["en"] is False else "?")
            t.add_row(f"[{col}]{r['rel']}[/]", self.fmt(r["target"]), r["type"] or "?", en)
        console.print(t)

    def run_hunt(self, name):
        q = f"""
        MATCH (t:Base) WHERE t.name=~'(?i).*{re.escape(name)}.*'
        MATCH (s:Base)-[r]->(t)
        WHERE NOT type(r) IN ['Contains','HasSession','GPLink']
        RETURN s.name AS source, type(r) AS rel, labels(s)[0] AS type, s.enabled AS en
        ORDER BY type(r), s.name"""
        with self.driver.session() as session:
            rows = self._qa(session, q)
        if not rows:
            console.print(f"[{C_DANGER}][!] No inbound edges for '{name}'[/]")
            return
        t = Table(title=f"[{C_DANGER}]🎯 Hunt: {name}[/]", border_style=C_DEEP)
        t.add_column("Source")
        t.add_column("Relationship", style="bold red", no_wrap=True)
        t.add_column("Type", style="dim")
        t.add_column("En", justify="center")
        for r in rows:
            col = REL_COLORS.get(r["rel"], C_FROST)
            en  = "✅" if r["en"] else ("❌" if r["en"] is False else "?")
            t.add_row(self.fmt(r["source"]), f"[{col}]{r['rel']}[/]", r["type"] or "?", en)
        console.print(t)

    # ── path (original approach: no edge type restriction) ─────────────────

    def _run_path_raw(self, start_pat, end_pat, hop, limit=1):
        """
        shortestPath with NO edge-type filter — matches original FrozenPath behavior.
        Finds paths the restricted version would miss.
        """
        q = f"""
        MATCH (start:Base) WHERE start.name=~'(?i).*{re.escape(start_pat)}.*'
        MATCH (end:Base)   WHERE end.name=~'(?i).*{re.escape(end_pat)}.*'
        WITH start, end WHERE ID(start) <> ID(end)
        MATCH p = shortestPath((start)-[*..{hop}]->(end))
        RETURN p, length(p) AS hops
        ORDER BY hops LIMIT {limit}
        """
        with self.driver.session() as session:
            try:
                return self._qa(session, q)
            except Exception as e:
                console.print(f"[{C_WARN}][!] Path query error: {e}[/]")
                return []

    def run_path(self, src, dst, hop=15):
        rows = self._run_path_raw(src, dst, hop, limit=1)
        if rows:
            self._display_path(rows[0]["p"],
                f"Exploit Chain: {src} → {dst}  [{rows[0]['hops']} hops]")
        else:
            console.print(f"[{C_DANGER}][!] No path found (max {hop} hops).[/]")

    def run_paths(self, src, dst, hop=10):
        rows = self._run_path_raw(src, dst, hop, limit=5)
        if not rows:
            console.print(f"[{C_DANGER}][!] No paths found (max {hop} hops).[/]")
            return
        for i, rec in enumerate(rows):
            self._display_path(rec["p"],
                f"[{i+1}/{len(rows)}] {src} → {dst}  [{rec['hops']} hops]")

    def _display_path(self, path, title):
        nodes = list(path.nodes)
        rels  = list(path.relationships)
        console.print(Panel(f"[{C_ICE}]{title}[/]", border_style=C_ICE, expand=False))
        for i, node in enumerate(nodes):
            name  = node.get("name", "Unknown")
            label = list(node.labels)[0] if node.labels else "Base"
            console.print(f"  [{C_GLOW}][ {i+1:02} ][/] {self.fmt(name)} [dim]({label})[/]")
            if i < len(rels):
                rel   = rels[i].type
                color = REL_COLORS.get(rel, C_FROST)
                console.print(f"       [{C_DEEP}]│[/]")
                console.print(f"       [{C_DEEP}]┝━━━[[/][{color}]{rel:^20}[/][{C_DEEP}]]━━━▶[/]")
                console.print(f"       [{C_DEEP}]│[/]")

    # ── dashboard ──────────────────────────────────────────────────────────

    def show_dashboard(self):
        """
        Full recon. Finds paths from current user (or all users) to ALL
        high-value targets present in this graph. Uses no edge restriction.
        """
        with self.driver.session() as session:
            # Discover targets present in this graph
            hv_targets = self._get_hv_targets(session)
            if not hv_targets:
                console.print(f"[{C_WARN}][!] No high-value targets found in graph.[/]")
                return

            # Determine source users
            if self.current_user:
                sources = [self.current_user]
            else:
                rows = self._qa(session, """
                    MATCH (u:User) WHERE u.enabled=true
                      AND NOT u.name=~'(?i).*(ADMINISTRATOR|KRBTGT|GUEST).*'
                    RETURN u.name AS name""")
                sources = [r["name"] for r in rows]
                console.print(f"[{C_ICE}]No current user set — scanning all {len(sources)} enabled users.[/]")
                console.print(f"[{C_ICE}]Use 'whoami <user>' to focus on a specific identity.[/]\n")

            # Quick intel table
            kerb  = self._qa(session, "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u.name AS n")
            asrep = self._qa(session, "MATCH (u:User {dontreqpreauth:true}) WHERE u.enabled=true RETURN u.name AS n")
            desc  = self._qa(session, """
                MATCH (n:Base) WHERE n.description IS NOT NULL AND n.description<>''
                  AND (toLower(n.description) CONTAINS 'pass' OR toLower(n.description) CONTAINS 'pwd'
                    OR toLower(n.description) CONTAINS 'cred' OR toLower(n.description) CONTAINS 'secret')
                RETURN n.name AS n, n.description AS d LIMIT 20""")
            dcs   = self._qa(session, """
                MATCH (n:Base)-[:GetChangesAll]->(d:Domain)
                WHERE NOT n.name=~'(?i).*(DOMAIN CONTROLLERS|ENTERPRISE DOMAIN CONTROLLERS).*'
                RETURN DISTINCT n.name AS n, labels(n)[0] AS t""")
            laps_readers = self._qa(session, """
                MATCH (s:Base)-[:ReadLAPSPassword|AllExtendedRights]->(c:Computer)
                WHERE c.haslaps=true
                  AND NOT s.name=~'(?i).*(DOMAIN ADMINS|ENTERPRISE ADMINS|ADMINISTRATORS).*'
                RETURN DISTINCT s.name AS n, c.name AS c LIMIT 10""")
            shadow = self._qa(session, """
                MATCH (s:Base)-[:AddKeyCredentialLink]->(t:Base)
                WHERE NOT s.name=~'(?i).*(DOMAIN ADMINS|ENTERPRISE ADMINS).*'
                RETURN DISTINCT s.name AS s, t.name AS t LIMIT 10""")

            intel = Table(
                title=f"[{C_DANGER}]🔥 Critical Intel[/]",
                border_style=C_DANGER, expand=True)
            intel.add_column("Category",  style=C_ICE)
            intel.add_column("Cnt",       justify="center", style=C_GOLD, no_wrap=True)
            intel.add_column("Details",   style=C_FROST)

            def _row(lbl, items, fn, color=None):
                cnt = len(items)
                det = "  ".join(fn(r) for r in items[:4]) + ("  …" if cnt > 4 else "") if cnt else "[dim]None[/]"
                intel.add_row(f"[{color}]{lbl}[/]" if color else lbl, str(cnt), det)

            _row("🎫 Kerberoastable",          kerb,         lambda r: r["n"])
            _row("🍖 AS-REP Roastable",         asrep,        lambda r: r["n"])
            _row("🔑 Pass in Description",      desc,         lambda r: f"{r['n']}: {str(r['d'])[:30]}", C_LAPS)
            _row("💀 DCSync Capable",            dcs,          lambda r: f"{r['n']}({r['t']})", C_DANGER)
            _row("🔐 LAPS Readers (non-admin)", laps_readers, lambda r: f"{r['n']}→{r['c']}", C_LAPS)
            _row("👻 Shadow Cred Paths",         shadow,       lambda r: f"{r['s']}→{r['t']}", C_PRIV)
            console.print(intel)

        # Auto-path scan: each source → each high-value target
        console.print(f"\n[{C_ICE}]🎯 High-Value Targets detected: "
                      f"[{C_GOLD}]{', '.join(n for n,_ in hv_targets)}[/][/]\n")

        found_any = False
        for uname in sources:
            for hv_name, hv_query in hv_targets:
                rows = self._run_path_raw(uname, hv_query, hop=15, limit=1)
                if rows:
                    found_any = True
                    self._display_path(rows[0]["p"],
                        f"AUTO: {uname} → {hv_name}  [{rows[0]['hops']} hops]")

        if not found_any:
            console.print(f"[{C_ICE}][i] No direct paths found to any high-value target.[/]")
            console.print(f"[{C_ICE}]    Try: path <user> to <target> --hop 20[/]")

    # ── acl / owned ────────────────────────────────────────────────────────

    def run_acl(self, target):
        ACL = "GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights|Owns|ForceChangePassword|AddMember|AddKeyCredentialLink"
        q = f"""
        MATCH (t:Base) WHERE t.name=~'(?i).*{re.escape(target)}.*'
        MATCH (s:Base)-[r:{ACL}]->(t)
        WHERE NOT s.name=~'(?i).*(DOMAIN ADMINS|ENTERPRISE ADMINS|ADMINISTRATORS).*'
        RETURN s.name AS src, type(r) AS rel, labels(s)[0] AS type
        ORDER BY type(r), s.name"""
        with self.driver.session() as session:
            rows = self._qa(session, q)
        if not rows:
            console.print(f"[{C_DANGER}][!] No ACL vectors for '{target}'[/]")
            return
        t = Table(title=f"[{C_ANOMALY}]⚡ ACL → {target}[/]", border_style=C_ANOMALY)
        t.add_column("Source")
        t.add_column("Right", style="bold yellow", no_wrap=True)
        t.add_column("Type", style="dim")
        for r in rows:
            col = REL_COLORS.get(r["rel"], C_FROST)
            t.add_row(self.fmt(r["src"]), f"[{col}]{r['rel']}[/]", r["type"] or "?")
        console.print(t)

    def run_owned(self, name):
        with self.driver.session() as session:
            res = self._q1(session,
                f"MATCH (n:Base) WHERE n.name=~'(?i).*{re.escape(name)}.*' RETURN n.name AS name LIMIT 1")
        if res:
            self.owned_nodes.add(res["name"])
            console.print(f"[{C_OK}]✔ Owned: {res['name']}  (total: {len(self.owned_nodes)})[/]")
        else:
            console.print(f"[{C_DANGER}][!] Not found: {name}[/]")

    # ── REPL ───────────────────────────────────────────────────────────────

    def start(self):
        console.clear()
        console.print(r"""
[#00B0FF]    ______                    ____       __  __   [/#00B0FF]
[#00E5FF]   / ____/________          / __ \____ _/ /_/ /_  [/#00E5FF]
[#18FFFF]  / /_  / ___/ __ \/_  /_  __ / /_/ / __ `/ __/ __ \ [/#18FFFF]
[#00E5FF] / __/ / /  / /_/ / / /_/ /__/ ____/ /_/ / /_/ / / / [/#00E5FF]
[#00B0FF]/_/   /_/   \____/ /___/\___/_/     \__,_/\__/_/ /_/  [/#00B0FF]
[bold white]    [ ❄️  FrozenPath v2.5.0 — Absolute Zero Tactical Suite ❄️  ] [/bold white]
[bold cyan]    [ OSCP Ready — No BloodHound Needed ] [/bold cyan]
""")
        self.quick_intel()
        console.print(f"\n[{C_ICE}]'help' for commands · 'whoami <user>' to set identity · 'dash' for full recon[/]\n")

        while True:
            try:
                label = f"[{self.current_user}]" if self.current_user else ""
                cmd   = self.session_prompt.prompt(f"crystal{label} > ").strip()
                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit"):
                    break

                parts = cmd.split()
                verb  = parts[0].lower()
                rest  = " ".join(parts[1:])

                if verb == "whoami" and rest:
                    self.run_whoami(rest)
                elif verb == "scout" and rest:
                    self.run_scout(rest)
                elif verb == "hunt" and rest:
                    self.run_hunt(rest)
                elif verb == "acl" and rest:
                    self.run_acl(rest)
                elif verb == "owned" and rest:
                    self.run_owned(rest)
                elif verb == "dash":
                    self.show_dashboard()
                elif m := re.match(
                    r"^paths?\s+(?P<s>.+?)\s+to\s+(?P<e>.+?)(?:\s+--hop\s+(?P<h>\d+))?$",
                    cmd, re.IGNORECASE
                ):
                    hop = int(m.group("h") or (10 if verb == "paths" else 15))
                    if verb == "paths":
                        self.run_paths(m.group("s"), m.group("e"), hop)
                    else:
                        self.run_path(m.group("s"), m.group("e"), hop)
                elif cmd in self.presets:
                    with self.driver.session() as s:
                        rows = list(s.run(self.presets[cmd]))
                    if not rows:
                        console.print(f"[{C_ICE}][i] No results.[/]")
                        continue
                    for r in rows:
                        vals = list(r.values())
                        if len(vals) == 1:
                            console.print(f" • {self.fmt(vals[0])}")
                        elif len(vals) == 2:
                            console.print(f" • {self.fmt(str(vals[0]))} [{C_ICE}]→[/] [{C_ICE}]{vals[1]}[/]")
                        else:
                            console.print(f" • {self.fmt(str(vals[0]))} | [{C_GOLD}]{vals[1]}[/] | {vals[2]}")
                elif verb == "help":
                    t = Table(title=f"[bold white]❄️ FrozenPath v2.5.0[/]", border_style=C_ICE)
                    t.add_column("Command",     style=C_GLOW, no_wrap=True)
                    t.add_column("Description")
                    t.add_row("whoami <user>",              "Set identity + full privilege check")
                    t.add_row("path <S> to <T> [--hop N]", "Shortest exploit path  (default: 15 hops)")
                    t.add_row("paths <S> to <T>",           "Top 5 shortest paths")
                    t.add_row("scout <target>",             "All outbound edges from target")
                    t.add_row("hunt <target>",              "All inbound edges to target")
                    t.add_row("acl <target>",               "ACL abuse vectors to target")
                    t.add_row("owned <name>",               "Mark node as owned")
                    t.add_row("dash",                       "Full recon: intel + auto-paths to all HV targets")
                    t.add_row("[dim]── presets ──[/dim]", "")
                    t.add_row("roast / kerberoast",         "AS-REP / Kerberoastable users")
                    t.add_row("laps / dcsync",              "LAPS computers / DCSync principals")
                    t.add_row("ls-admin / priv-users",      "DA members / privileged group members")
                    t.add_row("description / ls-sessions",  "Passwords in descriptions / active sessions")
                    console.print(t)
                else:
                    console.print(f"[{C_DANGER}][!] Unknown command. Type 'help'.[/]")

            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            except Exception as e:
                console.print(f"[{C_DANGER}][!] Error: {e}[/]")


if __name__ == "__main__":
    FrozenPath().start()
