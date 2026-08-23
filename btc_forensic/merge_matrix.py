#!/usr/bin/env python3
import csv, json, os, sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(__file__)
root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "matrix_aggregate")
outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "matrix_merged")
os.makedirs(outdir, exist_ok=True)

with open(os.path.join(HERE, "addresses.json"), encoding="utf-8") as f:
    cfg = json.load(f)
principal = set(cfg["garren_principal_23"])
cluster209 = {r["address"] for r in cfg["garren_cluster_209"]}
new8 = set(cfg["new_complaint_8"])
known = principal | cluster209 | new8

records = {}
for dp, _, files in os.walk(root):
    for fn in files:
        if not fn.startswith("address_") or not fn.endswith(".json"):
            continue
        p = os.path.join(dp, fn)
        try:
            with open(p, encoding="utf-8") as f:
                r = json.load(f)
            a = r.get("address")
            if a in known:
                old = records.get(a)
                if old is None or (old.get("status") != "OK" and r.get("status") == "OK"):
                    records[a] = r
        except Exception:
            pass

tx_by_id = {}
sources = defaultdict(set)
stats = {}
rows = []
for a in sorted(known):
    r = records.get(a)
    if not r:
        rows.append({"address": a, "status": "MISSING", "tx_count_fetched": "", "error": "No shard record"})
        continue
    status = r.get("status", "UNKNOWN")
    if status == "OK":
        stats[a] = r.get("stats", {})
        txs = r.get("txs", [])
        rows.append({"address": a, "status": "OK", "tx_count_fetched": len(txs), "error": ""})
        for tx in txs:
            txid = tx.get("txid")
            if not txid:
                continue
            src = tx.get("_fetch_sources", [])
            sources[txid].update(src)
            clean = dict(tx)
            clean.pop("_fetch_sources", None)
            tx_by_id[txid] = clean
    else:
        rows.append({"address": a, "status": status, "tx_count_fetched": 0, "error": r.get("error", "")})

with open(os.path.join(outdir, "raw_txs.jsonl"), "w", encoding="utf-8") as f:
    for txid in sorted(tx_by_id):
        rec = dict(tx_by_id[txid])
        rec["_fetch_sources"] = sorted(sources.get(txid, set()))
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

with open(os.path.join(outdir, "address_stats.json"), "w", encoding="utf-8") as f:
    json.dump(stats, f, separators=(",", ":"))

with open(os.path.join(outdir, "address_manifest.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["address", "status", "tx_count_fetched", "error"])
    w.writeheader(); w.writerows(rows)

ok = [r for r in rows if r["status"] == "OK"]
failed = [r for r in rows if r["status"] not in ("OK", "MISSING")]
missing = [r for r in rows if r["status"] == "MISSING"]
manifest = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "known_unique_address_count": len(known),
    "garren_principal_count": len(principal),
    "garren_209_count": len(cluster209),
    "new8_count": len(new8),
    "principal_209_overlap": len(principal & cluster209),
    "ok_address_count": len(ok),
    "failed_address_count": len(failed),
    "missing_address_count": len(missing),
    "unique_txids_fetched": len(tx_by_id),
    "failed_addresses": [r["address"] for r in failed],
    "missing_addresses": [r["address"] for r in missing],
}
with open(os.path.join(outdir, "merged_manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
print(json.dumps(manifest, indent=2))
