#!/usr/bin/env python3
"""Bulk-scan targets through the live HeaderGrade API and build seed.json.

Populates Grand totals (grade distribution) and Hall of fame (A / A+ sites).
Uses only the Python standard library.

Usage:
    python scan_targets.py <SEED_TOKEN> [COUNT]

The seed token matches the server's SEED_TOKEN env var and bypasses the public
rate limit so the seed run finishes quickly.
"""

import io
import json
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

API = "https://osint.cybercrew.co.jp/api/scan"
UMBRELLA = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
CONCURRENCY = 20

# Well-known sites scanned first so recognizable names land in the Hall of fame.
PRIORITY = [
    "google.com", "github.com", "cloudflare.com", "mozilla.org", "facebook.com",
    "x.com", "linkedin.com", "apple.com", "microsoft.com", "amazon.com",
    "wikipedia.org", "stripe.com", "paypal.com", "netflix.com", "youtube.com",
    "gov.uk", "digitalocean.com", "vercel.com", "netlify.com", "gitlab.com",
    "twitch.tv", "reddit.com", "instagram.com", "dropbox.com", "slack.com",
    "shopify.com", "wordpress.com", "yahoo.co.jp", "rakuten.co.jp", "mercari.com",
    "line.me", "note.com", "qiita.com", "hatena.ne.jp", "cybozu.com",
]


def fetch_domains(count):
    """Priority sites first, then the Umbrella top list, deduplicated."""
    domains, seen = [], set()
    for d in PRIORITY:
        if d not in seen:
            seen.add(d)
            domains.append(d)
    try:
        print("Downloading Umbrella top-1m list ...", flush=True)
        raw = urllib.request.urlopen(UMBRELLA, timeout=60).read()
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            with z.open(z.namelist()[0]) as f:
                for line in io.TextIOWrapper(f, "utf-8"):
                    parts = line.strip().split(",")
                    if len(parts) < 2:
                        continue
                    dom = parts[1].lower()
                    # Skip bare TLDs and obvious non-site hosts.
                    if dom.count(".") == 0 or dom in seen:
                        continue
                    seen.add(dom)
                    domains.append(dom)
                    if len(domains) >= count:
                        break
    except Exception as e:  # noqa: BLE001
        print(f"  (Umbrella download failed: {e}; using priority list only)", flush=True)
    return domains[:count]


def scan(domain, token):
    url = f"{API}?url={urllib.parse.quote(domain)}&seed={urllib.parse.quote(token)}&hide=1"
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HeaderGrade-Seeder/1.0"})
            with urllib.request.urlopen(req, timeout=40) as r:
                data = json.loads(r.read())
                return domain, data.get("grade")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 ** attempt)
                continue
            return domain, None
        except Exception:  # noqa: BLE001
            return domain, None
    return domain, None


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_targets.py <SEED_TOKEN> [COUNT]")
        sys.exit(1)
    token = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

    domains = fetch_domains(count)
    print(f"Scanning {len(domains)} targets with concurrency {CONCURRENCY} ...", flush=True)

    totals = {}
    good = []  # (order, host, grade) for A / A+
    errors = 0
    done = 0
    order = 0

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {pool.submit(scan, d, token): d for d in domains}
        for fut in as_completed(futures):
            host, grade = fut.result()
            done += 1
            if grade:
                totals[grade] = totals.get(grade, 0) + 1
                if grade in ("A+", "A"):
                    order += 1
                    good.append((order, host, grade))
            else:
                errors += 1
            if done % 100 == 0:
                print(f"  {done}/{len(domains)}  ok={done - errors} err={errors}", flush=True)

    # Hall of fame: priority sites first, newest timestamps at the front.
    prio_index = {d: i for i, d in enumerate(PRIORITY)}
    good.sort(key=lambda t: (prio_index.get(t[1], 10_000), t[0]))
    recent = []
    now = int(time.time())
    for i, (_, host, grade) in enumerate(good[:50]):
        ts = datetime.fromtimestamp(now - i * 60, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        recent.append({"host": host, "grade": grade, "scannedAt": ts})

    sites = {r["host"]: {"grade": r["grade"], "scannedAt": r["scannedAt"]} for r in recent}
    seed = {"totals": totals, "recent": recent, "sites": sites}
    with open("seed.json", "w", encoding="utf-8") as f:
        json.dump(seed, f, indent=2, ensure_ascii=False)

    print("\n===== GRADE DISTRIBUTION =====")
    for g in ["A+", "A", "B", "C", "D", "E", "F"]:
        print(f"{g:<4} {totals.get(g, 0)}")
    print(f"Total {sum(totals.values())}  (errors/no-site: {errors})")
    print(f"Hall of fame (A/A+): {len(good)} sites; wrote seed.json")


if __name__ == "__main__":
    main()
