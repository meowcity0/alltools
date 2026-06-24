# /// script
# dependencies = ["neo4j"]
# ///
import json, glob, os, time
from neo4j import GraphDatabase

# --- Connection Settings ---
# Change This
URI, USER, PW = "bolt://localhost:7687", "neo4j", "neo4j"
VERSION, CODENAME = "1.3.2", "Crystalline Silence"

# --- Visuals ---
C_BLUE, C_CYAN, C_WHITE = "\033[38;5;33m", "\033[38;5;123m", "\033[38;5;255m"
C_BOLD, C_RESET = "\033[1m", "\033[0m"

class CypherHound:
    def __init__(self):
        # 警告通知を抑制する設定でドライバを初期化
        self.driver = GraphDatabase.driver(URI, auth=(USER, PW))

    def run(self):
        start = time.time()
        print(f"\n{C_BOLD}{C_CYAN} 🧊 Snowfall v{VERSION} - {CODENAME}{C_RESET}")
        print(f"{C_BLUE}{'━'*55}{C_RESET}")

        with self.driver.session() as session:
            # DBのクリーンアップ
            print(f"{C_BLUE}[*] Purging Shadow Database...{C_RESET}")
            session.run("MATCH (n) DETACH DELETE n")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Base) REQUIRE n.objectid IS UNIQUE")

            files = sorted(glob.glob("*.json"))
            
            # Phase 1: Crystallize Nodes
            print(f"{C_BLUE}[*] Phase 1: Crystallizing Nodes...{C_RESET}")
            for f in files:
                label = self._get_label(f)
                with open(f, 'r', encoding='utf-8-sig') as j:
                    try: items = json.load(j).get('data', [])
                    except: continue
                    if not items: continue
                    q = (f"UNWIND $batch AS i MERGE (n:Base {{objectid: toUpper(i.ObjectIdentifier)}}) "
                         f"SET n += i.Properties, n:{label}, n.name = toUpper(i.Properties.name)")
                    session.run(q, batch=items)

            # Phase 2: Flowing Links (Warning-Free Optimized)
            print(f"{C_BLUE}[*] Phase 2: Flowing Relationships...{C_RESET}")
            for f in files:
                with open(f, 'r', encoding='utf-8-sig') as j:
                    try: items = json.load(j).get('data', [])
                    except: continue
                    self._links(session, items)

            self._stats(session)
        
        print(f"\n{C_BOLD}{C_CYAN}[+] Mission Accomplished in {time.time() - start:.2f}s{C_RESET}")
        print(f"{C_CYAN}[*] Path is now frozen. Start hunting in cypher-shell.{C_RESET}\n")

    def _get_label(self, p):
        n = os.path.basename(p).lower()
        m = {"user":"User", "computer":"Computer", "group":"Group", "domain":"Domain", "gpo":"GPO", "ou":"OU", "container":"Container"}
        return next((v for k, v in m.items() if k in n), "Base")

    def _links(self, session, items):
        if not items: return
        
        # 警告を回避するため、MATCHを個別に処理する構造に変更
        # 1. Memberships
        session.run("UNWIND $batch AS i "
                    "MATCH (g:Base {objectid: toUpper(i.ObjectIdentifier)}) "
                    "UNWIND i.Members AS m "
                    "WITH g, coalesce(m.ObjectIdentifier, m.MemberId, '') AS tid WHERE tid <> '' "
                    "MATCH (t:Base {objectid: toUpper(tid)}) "
                    "MERGE (t)-[:MemberOf]->(g)", batch=[x for x in items if x.get('Members')])

        # 2. PrimaryGroups
        session.run("UNWIND $batch AS i "
                    "MATCH (u:Base {objectid: toUpper(i.ObjectIdentifier)}) "
                    "MATCH (g:Base {objectid: toUpper(i.PrimaryGroupSID)}) "
                    "MERGE (u)-[:MemberOf]->(g)", batch=[x for x in items if x.get('PrimaryGroupSID')])

        # 3. GPO Links & Containers (Hidden Path Essentials)
        session.run("UNWIND $batch AS i "
                    "MATCH (t:Base {objectid: toUpper(i.ObjectIdentifier)}) "
                    "UNWIND coalesce(i.Links, []) AS l "
                    "MATCH (g:Base {objectid: toUpper(l.GUID)}) "
                    "MERGE (g)-[:GpLink]->(t)", batch=[x for x in items if x.get('Links')])

        session.run("UNWIND $batch AS i "
                    "MATCH (p:Base {objectid: toUpper(i.ObjectIdentifier)}) "
                    "UNWIND coalesce(i.ChildObjects, []) AS c "
                    "MATCH (child:Base {objectid: toUpper(c.ObjectIdentifier)}) "
                    "MERGE (p)-[:Contains]->(child)", batch=[x for x in items if x.get('ChildObjects')])

        # 4. ACLs (The Silent Merger)
        for i in [x for x in items if x.get('Aces')]:
            did = i['ObjectIdentifier'].upper()
            for a in i['Aces']:
                # 変数バインドを使い、文字列結合を避けることで警告を抑制
                session.run(f"MATCH (d:Base {{objectid: $did}}) "
                            f"MATCH (s:Base {{objectid: toUpper($sid)}}) "
                            f"MERGE (s)-[:{a['RightName']}]->(d)", did=did, sid=a['PrincipalSID'])

    def _stats(self, session):
        print(f"\n{C_WHITE}{C_BOLD}  FROZEN DATABASE SUMMARY{C_RESET}")
        print(f"{C_BLUE}{'━'*55}{C_RESET}")
        for r in session.run("MATCH (n) UNWIND labels(n) as l WITH l, count(*) as c WHERE l <> 'Base' RETURN l, c ORDER BY c DESC"):
            print(f"  {C_CYAN}{r['l']:<18} : {C_WHITE}{r['c']}{C_RESET}")
        print(f"{C_BLUE}{'-'*55}{C_RESET}")
        for r in session.run("MATCH ()-[r]->() RETURN type(r) as t, count(*) as c ORDER BY c DESC LIMIT 15"):
            print(f"  {C_CYAN}{r['t']:<20} : {C_WHITE}{r['c']}{C_RESET}")
        print(f"{C_BLUE}{'━'*55}{C_RESET}")

if __name__ == "__main__":
    CypherHound().run()
