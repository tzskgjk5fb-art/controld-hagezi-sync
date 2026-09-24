#!/usr/bin/env python3
"""
Build ControlD custom-rule folders (the JSON format HaGeZi publishes) from
plain-text / AdGuard-format blocklists, so controld-hagezi-sync can import them.

Output: one file per folder in folders/  (e.g. folders/android-tracking-folder.json)

Rule mapping (per Control D's docs, a rule for "x" already covers x AND all
its subdomains, so "*.x" duplicates are not emitted - this keeps the profile
under Control D's 10,000 custom-rule limit):
  ||x^ or |x^         -> block x
  @@||x^              -> allow x   (allow wins over block)
  plain / hosts lines -> block x
Skipped (ControlD can't express them): regex, mid-name wildcards, and modifiers
other than a positive $ctag=... (negative ctags like ~device_pc are skipped too,
because a ControlD folder can't be scoped per device type).

EXCLUDE lists below remove entries known to break common things. Edit freely.
Standard library only:  python3 scripts/build_folders.py
"""
import json, os, re, sys, urllib.request

RAW = "https://raw.githubusercontent.com"
SOURCES = [
    {
        "file": "perflyst-smarttv-folder.json", "group": "Perflyst SmartTV",
        "urls": [f"{RAW}/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
                 f"{RAW}/Perflyst/PiHoleBlocklist/master/SmartTV.txt"],
        "plain": "exact", "exclude": [],
    },
    {
        "file": "android-tracking-folder.json", "group": "Perflyst Android Tracking",
        "urls": [f"{RAW}/Perflyst/PiHoleBlocklist/master/android-tracking.txt"],
        "plain": "exact",
        # Facebook/Instagram/Messenger core app endpoints and broad Google hosts
        "exclude": ["a-graph.facebook.com", "graph.instagram.com", "mqtt-mini.facebook.com",
                    "appspot-preview.l.google.com", "id.google.de"],
    },
    {
        "file": "game-console-folder.json", "group": "Game Console Adblock",
        "urls": [f"{RAW}/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt"],
        "plain": "exact", "exclude": [],
    },
    {
        "file": "blocklistproject-smarttv-folder.json", "group": "BlocklistProject SmartTV",
        "urls": [f"{RAW}/blocklistproject/Lists/master/adguard/smart-tv-ags.txt"],
        "plain": "exact",
        # Perflyst notes these break Samsung TV connectivity/updates; Perflyst allows pavv
        "exclude": ["samsungcloudsolution.com", "samsungotn.net", "infolink.pavv.co.kr"],
    },
    {
        "file": "adguard-cname-targets-folder.json", "group": "AdGuard CNAME Targets",
        "urls": [f"{RAW}/AdguardTeam/cname-trackers/master/data/combined_original_trackers_justdomains.txt"],
        "plain": "wildcard",
        # bank/checkout fraud checks and email-marketing links
        "exclude": ["online-metrix.net", "exacttarget.com", "sailthru.com", "go.pardot.com",
                    "mailgun.org", "e.customeriomail.com"],
    },
    {
        "file": "stalkerware-folder.json", "group": "Stalkerware Indicators",
        "urls": [f"{RAW}/AssoEchap/stalkerware-indicators/master/generated/hosts"],
        "plain": "exact", "exclude": [],
    },
    {
        "file": "adguard-dns-popup-folder.json", "group": "AdGuard DNS Popup",
        "urls": [f"{RAW}/AdguardTeam/HostlistsRegistry/main/assets/filter_59.txt"],
        "plain": "exact", "exclude": [],
        # every rule in this list is ||x^$dnsrewrite=<AdGuard block host>, i.e. a block
        "rewrite_is_block": True,
    },
    {
        "file": "hagezi-doh-folder.json", "group": "HaGeZi DoH Bypass",
        "urls": [f"{RAW}/hagezi/dns-blocklists/main/adblock/doh.txt"],
        "plain": "exact",
        # Keep your own Control D endpoints reachable (e.g. phones using Control D
        # DoH/DoT on home Wi-Fi). Removes dns.controld.com and *.dns.controld.com.
        "exclude": ["dns.controld.com"],
    },
]

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
BLOCK, ALLOW = {"do": 0, "status": 1}, {"do": 1, "status": 1}
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "controld-folder-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace").lstrip("\ufeff")


def parse(text, plain_mode, skipped, rewrite_is_block=False):
    """Return (whole_blocks, exact_blocks, whole_allows)."""
    whole, exact, allow = set(), set(), set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "!#[" or line.startswith("/"):
            continue
        line = line.split(" #", 1)[0].strip().lower()
        is_allow = line.startswith("@@")
        if is_allow:
            line = line[2:]
        if "$" in line:
            line, mods = line.split("$", 1)
            if not all((m.startswith("ctag=") and "~" not in m)
                   or (rewrite_is_block and not is_allow and m.startswith("dnsrewrite="))
                   for m in mods.split(",")):
                skipped.append(raw.strip()); continue
        adblock = line.startswith("|")
        whole_rule = line.startswith("||")
        if adblock:
            name = line.lstrip("|").split("^")[0]
        else:
            parts = line.split()
            name = parts[1] if len(parts) >= 2 and parts[0] in HOSTS_IPS else parts[0]
            whole_rule = plain_mode == "wildcard"
        name = name.strip(".")
        if "*" in name or not DOMAIN_RE.match(name):
            skipped.append(raw.strip()); continue
        if is_allow:
            allow.add(name)
        elif whole_rule:
            whole.add(name)
        else:
            exact.add(name)
    return whole, exact, allow


def covered(name, domains):
    p = name.split(".")
    return any(".".join(p[i:]) in domains for i in range(len(p)))


def build(src, outdir):
    skipped = []
    whole, exact, allow = set(), set(), set()
    for url in src["urls"]:
        w, e, a = parse(fetch(url), src["plain"], skipped, src.get("rewrite_is_block", False))
        whole |= w; exact |= e; allow |= a
    ex = {d.lower() for d in src["exclude"]}
    whole -= ex; exact -= ex; allow -= ex

    rules = {}
    for d in sorted(whole):
        if not covered(d, allow):
            rules[d] = BLOCK
    for d in sorted(exact):
        if not covered(d, allow) and not covered(d, whole):
            rules[d] = BLOCK
    for d in sorted(allow):
        rules[d] = ALLOW

    if not rules:
        sys.exit(f"{src['group']}: no rules produced - refusing to write an empty folder")
    if len(src["group"]) > 32:
        sys.exit(f"{src['group']}: group name longer than ControlD's 32-character limit")
    folder = {"group": {"group": src["group"], "action": {"status": 1}},
              "rules": [{"PK": k, "action": v} for k, v in sorted(rules.items())]}
    path = os.path.join(outdir, src["file"])
    with open(path, "w") as f:
        json.dump(folder, f, indent=2); f.write("\n")
    nb = sum(v == BLOCK for v in rules.values())
    print(f"{src['group']}: {len(rules)} rules ({nb} block, {len(rules) - nb} allow) -> {path}")
    for s in skipped:
        print(f"    skipped: {s}")
    return len(rules)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "folders"
    os.makedirs(outdir, exist_ok=True)
    total = sum(build(s, outdir) for s in SOURCES)
    print(f"Total rules across folders: {total}")


if __name__ == "__main__":
    main()

