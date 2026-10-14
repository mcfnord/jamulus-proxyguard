#!/usr/bin/env python3
"""jamulus-proxyguard -- drop UDP from VPN/proxy exit addresses to a Jamulus server's port.

How: one nftables table, matching only UDP to the Jamulus port(s). The kernel records every sending address
in a set; this script reads that set twice a second, looks each new address up once at ip-api.com, and puts
`proxy` verdicts into a block set (remembered 7 days in /var/lib/jamulus-proxyguard/cache.json). A browsing
client pings the server before joining, so most addresses are judged before they connect.

Fails open: a lookup error, a rate limit or a stopped service blocks nobody; stopping deletes the table; a
firewall reload that wipes the table is undone within half a second. IPv4 only. Addresses listed in
/etc/jamulus-proxyguard/allow.txt (one address or CIDR per line) are never blocked or looked up.

  jamulus-proxyguard run --port 22124 [--port 22125] [--enforce]   # without --enforce: log only
  jamulus-proxyguard check 1.2.3.4                                 # one lookup, no firewall change
  jamulus-proxyguard status
"""
import ipaddress, json, os, re, subprocess, sys, time, urllib.request

TABLE = "jamulus_proxyguard"
CACHE = "/var/lib/jamulus-proxyguard/cache.json"
ALLOW = "/etc/jamulus-proxyguard/allow.txt"
TTL = 7 * 86400          # how long a verdict (and a block) lasts
SEEN = 600               # how long the kernel remembers an address as seen
URL = "http://ip-api.com/batch?fields=status,query,proxy,isp,as,countryCode"


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + msg, flush=True)


def nft(*args, script=None):
    cmd = ["nft"] + list(args) + (["-f", "-"] if script is not None else [])
    r = subprocess.run(cmd, input=script, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return r.returncode == 0, r.stdout + r.stderr


def ruleset(ports, enforce):
    p = ", ".join(map(str, ports))
    return """table inet %s {
  set allow { type ipv4_addr; flags interval; }
  set block { type ipv4_addr; flags timeout; }
  set seen { type ipv4_addr; flags dynamic, timeout; timeout %ds; size 65535; }
  chain input {
    type filter hook input priority -10; policy accept;
    udp dport { %s } ip saddr @allow accept
    udp dport { %s } ip saddr @block counter %s
    udp dport { %s } add @seen { ip saddr }
  }
}
""" % (TABLE, SEEN, p, p, "drop" if enforce else "", p)


def add(setname, elems):
    """elems: ['1.2.3.4', '5.6.7.8 timeout 60s', ...]"""
    return elems and nft(script="add element inet %s %s { %s }\n" % (TABLE, setname, ", ".join(elems)))


def seen_addresses():
    ok, out = nft("list", "set", "inet", TABLE, "seen")
    if not ok:
        return None
    m = re.search(r"elements = \{(.*?)\}", out, re.S)
    return [t.split()[0] for t in m.group(1).split(",") if t.split()] if m else []


def lookup(ips):
    """{ip: verdict} for the addresses ip-api answered; raises on any failure. Pauses when the budget runs out."""
    req = urllib.request.Request(URL, data=json.dumps(ips[:100]).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        rows, hdr = json.load(r), r.headers
    if hdr.get("X-Rl") == "0":
        lookup.pause = time.time() + int(hdr.get("X-Ttl", "60"))
    return {g["query"]: {"proxy": bool(g.get("proxy")), "as": g.get("as", ""), "isp": g.get("isp", ""),
                         "cc": g.get("countryCode", ""), "t": time.time()} for g in rows if g.get("status") == "success"}


lookup.pause = 0.0


def read_allow():
    nets = []
    if os.path.exists(ALLOW):
        for line in open(ALLOW):
            s = line.split("#")[0].strip()
            if s:
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    log("WARN ignoring bad line in %s: %r" % (ALLOW, s))
    return nets


def run(ports, enforce):
    os.makedirs(os.path.dirname(CACHE), 0o700, exist_ok=True)
    cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
    cache = {ip: v for ip, v in cache.items() if time.time() - v["t"] < TTL}
    allow = read_allow()

    def save():
        with open(CACHE + ".tmp", "w") as f:
            json.dump(cache, f)
        os.chmod(CACHE + ".tmp", 0o600)
        os.replace(CACHE + ".tmp", CACHE)

    def verdict(ip, v, how):
        if not v["proxy"]:
            return
        left = int(TTL - (time.time() - v["t"]))
        if enforce:
            add("block", ["%s timeout %ds" % (ip, max(left, 60))])
        log("%s ip=%s as=%r isp=%r cc=%s %s" % ("BLOCK" if enforce else "WOULD-BLOCK", ip, v["as"], v["isp"], v["cc"], how))

    def build():
        nft("delete", "table", "inet", TABLE)
        ok, err = nft(script=ruleset(ports, enforce))
        if not ok:
            raise SystemExit("FATAL nft refused the ruleset: " + err.strip())
        add("allow", [str(n) for n in allow])
        if enforce:
            add("block", ["%s timeout %ds" % (ip, max(int(TTL - (time.time() - v["t"])), 60))
                          for ip, v in cache.items() if v["proxy"]])

    build()
    log("START dry=%d ports=%s cached=%d allow=%d" % (not enforce, ",".join(map(str, ports)), len(cache), len(allow)))
    until = {}        # ip -> time until which it needs no attention
    try:
        while True:
            now = time.time()
            seen = seen_addresses()
            if seen is None:
                log("TABLE-MISSING (firewall reload?) -- rebuilding")
                build()
                seen = []
            todo = []
            for ip in seen:
                if until.get(ip, 0) > now or not ipaddress.ip_address(ip).is_global \
                        or any(ipaddress.ip_address(ip) in n for n in allow):
                    continue
                until[ip] = now + SEEN
                if ip in cache:
                    verdict(ip, cache[ip], "cached")
                else:
                    todo.append(ip)
            if todo and now >= lookup.pause:
                try:
                    res = lookup(todo)
                except Exception as e:
                    log("LOOKUP-FAIL n=%d err=%s (fail open; retry in 120 s)" % (len(todo), str(e)[:120]))
                    res = {}
                for ip in todo:
                    if ip in res:
                        cache[ip] = res[ip]
                        verdict(ip, res[ip], "looked-up")
                    else:
                        until[ip] = now + 120
                save()
            elif todo:
                for ip in todo:
                    until[ip] = now + 120
            until = {ip: t for ip, t in until.items() if t > now}
            time.sleep(0.5)
    finally:
        nft("delete", "table", "inet", TABLE)
        log("STOP table deleted (fail open)")


def main(argv):
    if argv[:1] == ["check"] and argv[1:]:
        for ip, v in lookup(argv[1:]).items():
            print(ip, "BLOCK" if v["proxy"] else "pass", v["as"], v["cc"])
        return 0
    if argv == ["status"]:
        ok, out = nft("list", "table", "inet", TABLE)
        print(out if ok else "table %s ABSENT: nothing is being blocked" % TABLE)
        return 0
    if argv[:1] == ["run"]:
        ports = [int(argv[i + 1]) for i, a in enumerate(argv) if a == "--port"]
        if ports and all(0 < p < 65536 for p in ports) and set(argv[1:]) <= {"--port", "--enforce"} | set(map(str, ports)):
            import signal
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            run(ports, "--enforce" in argv)
            return 0
    print(__doc__.strip(), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
