from collections import Counter
from pathlib import Path

p = Path(__file__).parent / "logs" / "access.log"
status = Counter()
paths = Counter()
ips = Counter()
newslist_429 = Counter()
newslist_200 = Counter()
hot_429 = 0
hot_200 = 0
total = 0
for line in p.open(encoding="utf-8", errors="ignore"):
    total += 1
    if '"' not in line:
        continue
    try:
        ip = line.split()[0]
        req = line.split('"')[1]
        parts = req.split()
        path = parts[1].split(";")[0].split("?")[0] if len(parts) >= 2 else ""
        tail = line.split('"', 2)[2].strip().split()
        st = tail[0] if tail else "?"
        status[st] += 1
        paths[path] += 1
        ips[ip] += 1
        if "/pub/newsList/" in path:
            lid = path.split("/pub/newsList/")[-1].split("/")[0]
            if st == "429":
                newslist_429[lid] += 1
            elif st == "200":
                newslist_200[lid] += 1
        if path.startswith("/pub/news/4") or any(
            path.startswith(f"/pub/newsList/{x}") for x in ("70", "81", "84", "100")
        ):
            if st == "429":
                hot_429 += 1
            elif st == "200":
                hot_200 += 1
    except Exception:
        pass

print("=== 沃盾 access.log ===")
print("Total:", total)
print("Status:", status.most_common(10))
print("Unique IPs:", len(ips))
print("429 rate: %.1f%%" % (100 * status.get("429", 0) / total if total else 0))
print()
print("Hot CC paths: 200=%d 429=%d" % (hot_200, hot_429))
print()
print("newsList IDs with most 429 (top 15):")
for lid, n in newslist_429.most_common(15):
    ok = newslist_200.get(lid, 0)
    print("  /pub/newsList/%s  429=%d  200=%d" % (lid, n, ok))
print()
print("newsList IDs with 200 but no 429 (sample, top 10):")
only_ok = [(lid, n) for lid, n in newslist_200.items() if newslist_429.get(lid, 0) == 0]
for lid, n in sorted(only_ok, key=lambda x: -x[1])[:10]:
    print("  /pub/newsList/%s  200=%d" % (lid, n))
