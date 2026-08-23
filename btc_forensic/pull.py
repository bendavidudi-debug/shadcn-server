#!/usr/bin/env python3
import csv, json, os, time, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

BASES = [("mempool.space", "https://mempool.space/api"), ("blockstream.info", "https://blockstream.info/api")]
HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

with open(os.path.join(HERE, "addresses.json"), encoding="utf-8") as f:
    cfg = json.load(f)
principal = set(cfg["garren_principal_23"])
cluster_rows = cfg["garren_cluster_209"]
cluster209 = {r["address"] for r in cluster_rows}
new8 = set(cfg["new_complaint_8"])
known = principal | cluster209 | new8
cluster_label = {r["address"]: r["label"] for r in cluster_rows}
address_origin = {}
for a in known:
    flags=[]
    if a in principal: flags.append("Garren principal")
    if a in cluster209: flags.append("Garren 209")
    if a in new8: flags.append("New complaint 8")
    address_origin[a] = " + ".join(flags)


def fetch_from(name, base, path, retries=3, timeout=25):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent":"BTC-forensic-research/2.1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode()), name
        except Exception as e:
            last = e
            time.sleep(min(1.5 * (2**attempt), 6))
    raise RuntimeError(f"{name} GET failed {path}: {last}")


def fetch_any(path, preferred=0):
    errs=[]
    order = BASES[preferred:] + BASES[:preferred]
    for name, base in order:
        try:
            return fetch_from(name, base, path)
        except Exception as e:
            errs.append(str(e))
    raise RuntimeError(" | ".join(errs))


def fetch_stats(addr):
    out={}
    for name, base in BASES:
        try:
            d,_ = fetch_from(name, base, f"/address/{addr}", retries=2, timeout=20)
            out[name]=d
        except Exception as e:
            out[name]={"_error":str(e)}
    return out


def fetch_address(addr, ordinal):
    preferred = ordinal % 2
    txs=[]; seen=set(); sources=defaultdict(set); last=None
    while True:
        path=f"/address/{addr}/txs/chain" + (f"/{last}" if last else "")
        page, src = fetch_any(path, preferred)
        if not page: break
        for tx in page:
            txid=tx["txid"]; sources[txid].add(src)
            if txid not in seen:
                txs.append(tx); seen.add(txid)
        if len(page)<25: break
        last=page[-1]["txid"]
        time.sleep(0.02)
    try:
        page,src=fetch_any(f"/address/{addr}/txs/mempool", preferred)
        for tx in page:
            txid=tx["txid"]; sources[txid].add(src)
            if txid not in seen:
                txs.append(tx); seen.add(txid)
    except Exception:
        pass
    return addr, fetch_stats(addr), txs, sources

addresses=sorted(known)
all_txs={}; all_tx_sources=defaultdict(set); address_stats={}; failures=[]
max_workers=int(os.environ.get("BTC_WORKERS","10"))
with ThreadPoolExecutor(max_workers=max_workers) as ex:
    futs={ex.submit(fetch_address,a,i):a for i,a in enumerate(addresses)}
    done=0
    for fut in as_completed(futs):
        a=futs[fut]; done+=1
        try:
            addr,stats,txs,sources=fut.result(); address_stats[addr]=stats
            for tx in txs:
                txid=tx["txid"]; all_txs[txid]=tx; all_tx_sources[txid].update(sources.get(txid,set()))
            print(f"[{done}/{len(addresses)}] {addr} txs={len(txs)} unique_global={len(all_txs)}", flush=True)
        except Exception as e:
            failures.append((a,str(e))); print("FAIL",a,e,flush=True)

# Preserve raw transaction payloads so final analysis is reproducible.
with open(os.path.join(OUT,"raw_txs.jsonl"),"w",encoding="utf-8") as f:
    for txid in sorted(all_txs):
        rec=dict(all_txs[txid]); rec["_fetch_sources"]=sorted(all_tx_sources[txid])
        f.write(json.dumps(rec,separators=(",",":"))+"\n")
with open(os.path.join(OUT,"address_stats.json"),"w",encoding="utf-8") as f:
    json.dump(address_stats,f,separators=(",",":"))


def vout_addr(v): return v.get("scriptpubkey_address")
def block_time(tx): return (tx.get("status") or {}).get("block_time")

tx_rows=[]; external_rows=[]; internal_rows=[]; mixed_rows=[]
addr_receipts=defaultdict(lambda:{"gross_sat":0,"external_sat":0,"internal_sat":0,"mixed_sat":0,"receipt_txs":set()})
for txid,tx in all_txs.items():
    known_input_addrs=set(); external_input_addrs=set(); unknown_script_input_sat=0
    known_in_sat=0; external_in_sat=0
    for vin in tx.get("vin",[]):
        p=vin.get("prevout") or {}; a=p.get("scriptpubkey_address"); val=p.get("value") or 0
        if a in known:
            known_input_addrs.add(a); known_in_sat+=val
        else:
            if a: external_input_addrs.add(a)
            else: unknown_script_input_sat+=val
            external_in_sat+=val
    known_outputs=[]; total_known_out=0
    for idx,v in enumerate(tx.get("vout",[])):
        a=vout_addr(v); val=v.get("value") or 0
        if a in known:
            known_outputs.append((a,idx,val)); total_known_out+=val
            d=addr_receipts[a]; d["gross_sat"]+=val; d["receipt_txs"].add(txid)
    if not known_outputs: continue
    if known_in_sat==0: flow="EXTERNAL_ONLY"
    elif external_in_sat==0: flow="ATTACKER_INTERNAL_ONLY"
    else: flow="MIXED_INPUTS"
    t=block_time(tx); dt=datetime.fromtimestamp(t,tz=timezone.utc).isoformat() if t else ""
    row={"txid":txid,"block_time_utc":dt,"flow_class":flow,"known_attacker_output_btc":total_known_out/1e8,
         "known_attacker_input_btc":known_in_sat/1e8,"external_unknown_input_btc":external_in_sat/1e8,
         "known_input_addresses":";".join(sorted(known_input_addrs)),"external_input_addresses":";".join(sorted(external_input_addrs)),
         "unknown_script_input_btc":unknown_script_input_sat/1e8,"attacker_output_addresses":";".join(a for a,_,_ in known_outputs),
         "attacker_output_detail":";".join(f"{a}:{idx}:{val/1e8:.8f}" for a,idx,val in known_outputs),
         "fetch_sources":";".join(sorted(all_tx_sources.get(txid,set())))}
    tx_rows.append(row)
    if flow=="EXTERNAL_ONLY": external_rows.append(row)
    elif flow=="ATTACKER_INTERNAL_ONLY": internal_rows.append(row)
    else: mixed_rows.append(row)
    for a,idx,val in known_outputs:
        key={"EXTERNAL_ONLY":"external_sat","ATTACKER_INTERNAL_ONLY":"internal_sat","MIXED_INPUTS":"mixed_sat"}[flow]
        addr_receipts[a][key]+=val

# Simple chronological gap waves; final workbook can refine after review.
ext_sorted=sorted([r for r in external_rows if r["block_time_utc"]],key=lambda x:x["block_time_utc"])
wave=0; prev=None
for r in ext_sorted:
    cur=datetime.fromisoformat(r["block_time_utc"])
    if prev is None or (cur-prev).total_seconds()>14*86400: wave+=1
    r["wave"]=f"Wave {wave}"; prev=cur
for r in external_rows:
    r.setdefault("wave","")


def write_csv(name,rows,fields):
    with open(os.path.join(OUT,name),"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})

tx_fields=["txid","block_time_utc","flow_class","known_attacker_output_btc","known_attacker_input_btc","external_unknown_input_btc","unknown_script_input_btc","known_input_addresses","external_input_addresses","attacker_output_addresses","attacker_output_detail","fetch_sources"]
write_csv("all_known_inbound_txs.csv",sorted(tx_rows,key=lambda r:r["block_time_utc"]),tx_fields)
ext_fields=["wave","block_time_utc","txid","external_input_addresses","attacker_output_addresses","known_attacker_output_btc","external_unknown_input_btc","unknown_script_input_btc","fetch_sources"]
write_csv("external_first_touch.csv",sorted(external_rows,key=lambda r:r["block_time_utc"]),ext_fields)
write_csv("internal_attacker_transfers.csv",sorted(internal_rows,key=lambda r:r["block_time_utc"]),tx_fields)
write_csv("mixed_input_transfers.csv",sorted(mixed_rows,key=lambda r:r["block_time_utc"]),tx_fields)

addr_rows=[]
for a in addresses:
    stats=address_stats.get(a,{})
    preferred=stats.get("mempool.space",{}) if not stats.get("mempool.space",{}).get("_error") else stats.get("blockstream.info",{})
    cs=preferred.get("chain_stats",{}) if isinstance(preferred,dict) else {}
    d=addr_receipts[a]
    addr_rows.append({"address":a,"origin":address_origin[a],"cluster":cluster_label.get(a,""),"chain_tx_count":cs.get("tx_count",""),
        "chain_funded_btc":(cs.get("funded_txo_sum",0) or 0)/1e8,"chain_spent_btc":(cs.get("spent_txo_sum",0) or 0)/1e8,
        "reconstructed_gross_btc":d["gross_sat"]/1e8,"external_first_touch_btc":d["external_sat"]/1e8,
        "attacker_internal_received_btc":d["internal_sat"]/1e8,"mixed_received_btc":d["mixed_sat"]/1e8,"receipt_tx_count":len(d["receipt_txs"]),
        "is_garren_principal":a in principal,"is_garren_209":a in cluster209,"is_new8":a in new8})
write_csv("address_summary.csv",addr_rows,list(addr_rows[0].keys()))

with open(os.path.join(OUT,"failures.csv"),"w",newline="",encoding="utf-8") as f:
    w=csv.writer(f); w.writerow(["address","error"]); w.writerows(failures)

gross=sum(r["known_attacker_output_btc"] for r in tx_rows)
external=sum(r["known_attacker_output_btc"] for r in external_rows)
internal=sum(r["known_attacker_output_btc"] for r in internal_rows)
mixed=sum(r["known_attacker_output_btc"] for r in mixed_rows)
summary={"generated_utc":datetime.now(timezone.utc).isoformat(),"known_unique_addresses":len(known),"garren_principal_23":len(principal),
    "garren_209":len(cluster209),"new8":len(new8),"principal_209_overlap":len(principal & cluster209),
    "all_unique_txids_touching_known_addresses":len(all_txs),"gross_receipts_reconstructed_btc":round(gross,8),
    "external_only_first_touch_btc":round(external,8),"attacker_internal_receipts_btc":round(internal,8),
    "mixed_input_receipts_btc":round(mixed,8),"external_only_tx_count":len(external_rows),
    "attacker_internal_tx_count":len(internal_rows),"mixed_input_tx_count":len(mixed_rows),"failure_count":len(failures),"failures":failures,
    "method":"Fresh Esplora transaction pulls from mempool.space and blockstream.info. EXTERNAL_ONLY has no known attacker input; ATTACKER_INTERNAL_ONLY has known attacker inputs and no external inputs; MIXED_INPUTS has both and is excluded from conservative unique first-touch total."}
with open(os.path.join(OUT,"summary.json"),"w",encoding="utf-8") as f: json.dump(summary,f,indent=2)
print(json.dumps(summary,indent=2),flush=True)
