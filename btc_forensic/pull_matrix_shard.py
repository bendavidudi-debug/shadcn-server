#!/usr/bin/env python3
import json, os, time, urllib.request
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
cluster209 = {r["address"] for r in cfg["garren_cluster_209"]}
new8 = set(cfg["new_complaint_8"])
known = principal | cluster209 | new8
all_addresses = sorted(known)
targets = all_addresses[SHARD_INDEX::SHARD_COUNT]

outdir = os.path.join(HERE, "matrix_out", f"shard_{SHARD_INDEX:03d}")
os.makedirs(outdir, exist_ok=True)


def atomic_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"))
    os.replace(tmp, path)


def fetch_from(name, base, path, retries=3, timeout=15):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": "BTC-forensic-research/3.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode()), name
        except Exception as e:
            last = e
            time.sleep(min(1.0 * (2 ** attempt), 4))
    raise RuntimeError(f"{name} GET failed {path}: {last}")


def fetch_any(path, preferred=0):
    errors = []
    order = BASES[preferred:] + BASES[:preferred]
    for name, base in order:
        try:
            return fetch_from(name, base, path)
        except Exception as e:
            errors.append(str(e))
    raise RuntimeError(" | ".join(errors))


def fetch_stats_both(addr):
    out = {}
    for name, base in BASES:
        try:
            data, _ = fetch_from(name, base, f"/address/{addr}", retries=2, timeout=12)
            out[name] = data
        except Exception as e:
            out[name] = {"_error": str(e)}
    return out


def fetch_address_txs(addr, preferred):
    txs = []
    seen = set()
    sources = defaultdict(set)
    last = None
    pages = 0
    while True:
        path = f"/address/{addr}/txs/chain" + (f"/{last}" if last else "")
        page, source = fetch_any(path, preferred)
        pages += 1
        if not page:
            break
        for tx in page:
            txid = tx["txid"]
            sources[txid].add(source)
            if txid not in seen:
                txs.append(tx)
                seen.add(txid)
        if len(page) < 25:
            break
        last = page[-1]["txid"]
        time.sleep(0.05)
    try:
        page, source = fetch_any(f"/address/{addr}/txs/mempool", preferred)
        for tx in page:
            txid = tx["txid"]
            sources[txid].add(source)
            if txid not in seen:
                txs.append(tx)
                seen.add(txid)
    except Exception:
        pass
    records = []
    for tx in txs:
        rec = dict(tx)
        rec["_fetch_sources"] = sorted(sources.get(tx["txid"], set()))
        records.append(rec)
    return records, pages


def write_manifest(rows):
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
        "targets": targets,
        "rows": rows,
    }
    atomic_json(os.path.join(outdir, "manifest.json"), manifest)

rows = []
write_manifest(rows)
for n, addr in enumerate(targets, 1):
    preferred = (SHARD_INDEX + n) % 2
    started = time.time()
    rec_path = os.path.join(outdir, f"address_{addr}.json")
    try:
        stats = fetch_stats_both(addr)
        txs, pages = fetch_address_txs(addr, preferred)
        payload = {
            "address": addr,
            "status": "OK",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
            "txs": txs,
            "tx_count_fetched": len(txs),
            "pages_fetched": pages,
        }
        atomic_json(rec_path, payload)
        row = {"address": addr, "status": "OK", "tx_count_fetched": len(txs), "pages_fetched": pages, "elapsed_sec": round(time.time()-started, 2)}
        rows.append(row)
        write_manifest(rows)
        print(f"shard {SHARD_INDEX}/{SHARD_COUNT} [{n}/{len(targets)}] OK {addr} txs={len(txs)} pages={pages} sec={row['elapsed_sec']}", flush=True)
    except Exception as e:
        payload = {
            "address": addr,
            "status": "FAIL",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }
        atomic_json(rec_path, payload)
        row = {"address": addr, "status": "FAIL", "error": str(e), "elapsed_sec": round(time.time()-started, 2)}
        rows.append(row)
        write_manifest(rows)
        print(f"shard {SHARD_INDEX}/{SHARD_COUNT} [{n}/{len(targets)}] FAIL {addr}: {e}", flush=True)

print(json.dumps({"shard": SHARD_INDEX, "targets": len(targets), "ok": sum(r['status']=='OK' for r in rows), "fail": sum(r['status']!='OK' for r in rows)}), flush=True)
