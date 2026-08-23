#!/usr/bin/env python3
import csv, json, os, time, urllib.request, urllib.error
from collections import defaultdict
from datetime import datetime, timezone

BASES = [
    ("mempool.space", "https://mempool.space/api"),
    ("blockstream.info", "https://blockstream.info/api"),
]
HERE = os.path.dirname(__file__)
SHARD_INDEX = int(os.environ.get("SHARD_INDEX", "0"))
SHARD_COUNT = int(os.environ.get("SHARD_COUNT", "1"))

with open(os.path.join(HERE, "addresses.json"), encoding="utf-8") as f:
    cfg = json.load(f)
principal = set(cfg["garren_principal_23"])
cluster_rows = cfg["garren_cluster_209"]
cluster209 = {r["address"] for r in cluster_rows}
new8 = set(cfg["new_complaint_8"])
known = principal | cluster209 | new8
all_addresses = sorted(known)
targets = all_addresses[SHARD_INDEX::SHARD_COUNT]

outdir = os.path.join(HERE, "out", f"shard_{SHARD_INDEX:02d}")
os.makedirs(outdir, exist_ok=True)


def fetch_from(name, base, path, retries=4, timeout=20):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": "BTC-forensic-research/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode()), name
        except Exception as e:
            last = e
            time.sleep(min(1.5 * (2 ** attempt), 8))
    raise RuntimeError(f"{name} GET failed {path}: {last}")


def fetch_any(path, preferred=0):
    errs = []
    order = BASES[preferred:] + BASES[:preferred]
    for name, base in order:
        try:
            return fetch_from(name, base, path)
        except Exception as e:
            errs.append(str(e))
    raise RuntimeError(" | ".join(errs))


def fetch_stats_both(addr):
    result = {}
    for name, base in BASES:
        try:
            data, _ = fetch_from(name, base, f"/address/{addr}", retries=3, timeout=18)
            result[name] = data
        except Exception as e:
            result[name] = {"_error": str(e)}
    return result


def addr_txs(addr, preferred):
    out = []
    seen = set()
    tx_sources = defaultdict(set)
    last = None
    while True:
        path = f"/address/{addr}/txs/chain" + (f"/{last}" if last else "")
        page, source = fetch_any(path, preferred)
        if not page:
            break
        for tx in page:
            txid = tx["txid"]
            tx_sources[txid].add(source)
            if txid not in seen:
                out.append(tx)
                seen.add(txid)
        if len(page) < 25:
            break
        last = page[-1]["txid"]
        time.sleep(0.03)
    try:
        page, source = fetch_any(f"/address/{addr}/txs/mempool", preferred)
        for tx in page:
            txid = tx["txid"]
            tx_sources[txid].add(source)
            if txid not in seen:
                out.append(tx)
                seen.add(txid)
    except Exception:
        pass
    return out, tx_sources


all_txs = {}
all_tx_sources = defaultdict(set)
address_stats = {}
failures = []
address_manifests = []

for n, addr in enumerate(targets, 1):
    preferred = (SHARD_INDEX + n) % 2
    try:
        stats = fetch_stats_both(addr)
        address_stats[addr] = stats
        txs, tx_sources = addr_txs(addr, preferred)
        for tx in txs:
            txid = tx["txid"]
            all_txs[txid] = tx
            all_tx_sources[txid].update(tx_sources.get(txid, set()))
        address_manifests.append({"address": addr, "tx_count_fetched": len(txs), "status": "OK"})
        print(f"shard {SHARD_INDEX}/{SHARD_COUNT} [{n}/{len(targets)}] {addr} txs={len(txs)} shard_unique={len(all_txs)}", flush=True)
    except Exception as e:
        failures.append((addr, str(e)))
        address_manifests.append({"address": addr, "tx_count_fetched": 0, "status": "FAIL", "error": str(e)})
        print("FAIL", addr, e, flush=True)

with open(os.path.join(outdir, "raw_txs.jsonl"), "w", encoding="utf-8") as f:
    for txid in sorted(all_txs):
        rec = dict(all_txs[txid])
        rec["_fetch_sources"] = sorted(all_tx_sources[txid])
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

with open(os.path.join(outdir, "address_stats.json"), "w", encoding="utf-8") as f:
    json.dump(address_stats, f, separators=(",", ":"))

with open(os.path.join(outdir, "address_manifest.csv"), "w", newline="", encoding="utf-8") as f:
    fields = ["address", "tx_count_fetched", "status", "error"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in address_manifests:
        w.writerow({k: r.get(k, "") for k in fields})

with open(os.path.join(outdir, "failures.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["address", "error"])
    w.writerows(failures)

manifest = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "shard_index": SHARD_INDEX,
    "shard_count": SHARD_COUNT,
    "target_count": len(targets),
    "known_unique_address_count": len(known),
    "garren_principal_count": len(principal),
    "garren_209_count": len(cluster209),
    "new8_count": len(new8),
    "principal_209_overlap": len(principal & cluster209),
    "unique_txids_fetched_in_shard": len(all_txs),
    "failure_count": len(failures),
    "targets": targets,
}
with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
print(json.dumps(manifest, indent=2), flush=True)
