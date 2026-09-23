#!/usr/bin/env python3
"""
Merge Perflyst's SmartTV.txt (Pi-hole) and SmartTV-AGH.txt (AdGuard Home)
into a single ControlD custom-rule folder (same JSON format HaGeZi publishes).

Rules produced:
  ||example.com^    (AGH)  -> block  example.com  AND  *.example.com
  |example.com^     (AGH)  -> block  example.com  (exact only)
  @@||example.com^  (AGH)  -> allow  example.com  AND  *.example.com
  host.example.com  (Pi-hole list) -> block exact host, unless already covered
                                      by an AGH wildcard block

Notes:
  * ControlD's "*.domain" matches subdomains but NOT the root domain,
    which is why whole-domain rules emit both forms.
  * Allow rules win over blocks for the same name (they exist to prevent breakage).
  * Mid-name wildcards (e.g. api.*.hismarttv.com) and Perflyst's regex.list
    can't be expressed as ControlD custom rules and are skipped (reported below).

Standard library only. Usage:
  python3 build_smarttv_folder.py [-o folders/perflyst-smarttv-folder.json]
"""
import argparse, json, re, sys, urllib.request

PIHOLE_URL = "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"
AGH_URL = "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt"
GROUP_NAME = "Perflyst SmartTV"          # must be <= 32 chars for ControlD
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

BLOCK = {"do": 0, "status": 1}
ALLOW = {"do": 1, "status": 1}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "smarttv-folder-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def valid(d):
    return bool(DOMAIN_RE.match(d))


def parse_agh(text, skipped):
    wild_block, exact_block, wild_allow = set(), set(), set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        allow = line.startswith("@@")
        if allow:
            line = line[2:]
        if "$" in line:
            line, mods = line.split("$", 1)
            # $ctag=device_tv just scopes a rule to TVs in AdGuard Home; this folder
            # is meant for a TV profile, so keep those. Any other modifier: skip.
            if not all(m.startswith("ctag=") for m in mods.split(",")):
                skipped.append(raw.strip()); continue
        whole = line.startswith("||")
        name = line.lstrip("|").split("^")[0].strip(".")
        if "*" in name or not valid(name):
            skipped.append(raw.strip()); continue
        if allow:
            wild_allow.add(name)             # @@||x^ and @@|x^ both treated as x + *.x
        elif whole:
            wild_block.add(name)
        else:
            exact_block.add(name)
    return wild_block, exact_block, wild_allow


def parse_pihole(text, skipped):
    hosts = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            line = parts[1]
        else:
            line = parts[0]
        line = line.strip(".")
        if "*" in line or not valid(line):
            skipped.append(raw.strip()); continue
        hosts.add(line)
    return hosts


def covered(name, wild):
    parts = name.split(".")
    return any(".".join(parts[i:]) in wild for i in range(len(parts)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="folders/perflyst-smarttv-folder.json")
    args = ap.parse_args()

    skipped = []
    wild_block, exact_block, wild_allow = parse_agh(fetch(AGH_URL), skipped)
    pihole = parse_pihole(fetch(PIHOLE_URL), skipped)

    rules = {}  # PK -> action

    def put(pk, action):
        # allow always wins over block for the same key
        if rules.get(pk) == ALLOW:
            return
        rules[pk] = action

    for d in wild_block:
        if covered(d, wild_allow):
            continue
        put(d, BLOCK); put("*." + d, BLOCK)
    for d in exact_block:
        if not covered(d, wild_allow):
            put(d, BLOCK)
    added_pihole = 0
    for h in pihole:
        if covered(h, wild_allow) or covered(h, wild_block):
            continue
        put(h, BLOCK); added_pihole += 1
    for d in wild_allow:
        rules[d] = ALLOW; rules["*." + d] = ALLOW

    folder = {
        "group": {"group": GROUP_NAME, "action": {"status": 1}},
        "rules": [{"PK": pk, "action": act} for pk, act in sorted(rules.items())],
    }
    import os
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(folder, f, indent=2)
        f.write("\n")

    n_block = sum(1 for a in rules.values() if a == BLOCK)
    n_allow = len(rules) - n_block
    print(f"AGH: {len(wild_block)} whole-domain blocks, {len(exact_block)} exact blocks, {len(wild_allow)} allows")
    print(f"Pi-hole list: {len(pihole)} hosts, {added_pihole} not already covered by AGH wildcards")
    print(f"Wrote {args.output}: {len(rules)} rules ({n_block} block, {n_allow} allow)")
    if skipped:
        print(f"Skipped {len(skipped)} entries ControlD can't express:")
        for s in skipped:
            print("   ", s)
    if len(rules) == 0:
        sys.exit("No rules produced - refusing to write an empty folder")


if __name__ == "__main__":
    main()
