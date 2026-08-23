#!/usr/bin/env python3
import csv, json, os, sys, time, urllib.request, urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

BASES = ["https://blockstream.info/api", "https://mempool.space/api"]
ROOT = os.path.dirname(__file__)
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)

with open(os.path.join(ROOT, "addresses.json"), encoding="utf-8") as f:
    data = json.load(f)

meta = {}
for x in data["principal23"]:
    meta.setdefault(x["address"], {"address":x["address"],"principal":False,"supplement":False,"new8":False,"labels":[],"clusters":[]})
    meta[x["address"]]["principal"] = True
    meta[x["address"]]["labels"].append(x["label"])
for x in data["supplement209"]:
    meta.setdefault(x["address"], {"address":x["address"],"principal":False,"supplement":False,"new8":False,"labels":[],"clusters":[]})
    meta[x["address"]]["supplement"] = True
    meta[x["address"]]["clusters"].append(x["cluster"])
for x in data["new8"]:
    meta.setdefault(x["address"], {"address":x["address"],"principal":False,"supplement":False,"new8":False,"labels":[],"clusters":[]})
    meta[x["address"]]["new8"] = True
    meta[x["address"]]["labels"].append(x["label"])
TARGET = set(meta)

UA = "Mozilla/5.0 BTC-forensic-audit/1.0"
def get_json(path, retries=8):
    last = None
    for attempt in range(retries):
        for base in BASES:
            try:
                req = urllib.request.Request(base + path, headers={"User-Agent":UA,"Accept":"application/json"})
                with urllib.request.urlopen(req, timeout=45) as r:
                    b = r.read()
                    return json.loads(b.decode("utf-8"))
            except Exception as e:
                last = e
                time.sleep(min(2**attempt, 20))
    raise RuntimeError(f"GET failed {path}: {last}")

def fetch_address_txs(addr):
    alltx=[]
    page = get_json("/address/" + urllib.parse.quote(addr, safe="") + "/txs")
    alltx.extend(page)
    while len(page) == 25:
        last = page[-1]["txid"]
        page = get_json("/address/" + urllib.parse.quote(addr, safe="") + "/txs/chain/" + last)
        if not page: break
        alltx.extend(page)
    # de-dupe preserving newest-first order
    seen=set(); out=[]
    for t in alltx:
        if t["txid"] not in seen:
            seen.add(t["txid"]); out.append(t)
    return out

def addr_from_prevout(p):
    if not p: return None
    return p.get("scriptpubkey_address")
def addr_from_vout(v):
    return v.get("scriptpubkey_address")

def block_time(tx):
    st=tx.get("status") or {}
    return st.get("block_time")

def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else ""

# Pull all address histories; cache unique transactions from the explorer responses.
all_txs={}
address_seen=defaultdict(set)
for i,addr in enumerate(sorted(TARGET),1):
    print(f"[{i}/{len(TARGET)}] {addr}", flush=True)
    txs=fetch_address_txs(addr)
    for tx in txs:
        all_txs[tx["txid"]]=tx
        address_seen[addr].add(tx["txid"])
    time.sleep(0.08)

# If any tx object lacks prevout details (should not happen with Esplora), refetch it.
for txid,tx in list(all_txs.items()):
    if any(v.get("prevout") is None and not v.get("is_coinbase") for v in tx.get("vin",[])):
        all_txs[txid]=get_json("/tx/"+txid)

# Aggregate transaction boundary measures.
tx_rows=[]
first_touch=[]
internal_rows=[]
addr_stats={a:{
    "tx_touch_count":0,"gross_received_sats":0,"gross_sent_input_sats":0,
    "external_direct_received_sats":0,"internal_received_sats":0,
    "first_seen":None,"last_seen":None,"external_direct_tx_count":0,"internal_receive_tx_count":0
} for a in TARGET}

# DSU for external source addresses co-spent in first-touch txs.
parent={}
def find(x):
    parent.setdefault(x,x)
    while parent[x]!=x:
        parent[x]=parent[parent[x]]; x=parent[x]
    return x
def union(a,b):
    ra,rb=find(a),find(b)
    if ra!=rb: parent[rb]=ra

for txid,tx in all_txs.items():
    ts=block_time(tx)
    vins=tx.get("vin",[]); vouts=tx.get("vout",[])
    u_in=[]; ext_in=[]; unknown_inputs=0
    total_from_u=0
    for vin in vins:
        if vin.get("is_coinbase"):
            continue
        p=vin.get("prevout") or {}
        a=addr_from_prevout(p); val=int(p.get("value") or 0)
        if a in TARGET:
            u_in.append((a,val)); total_from_u += val
        else:
            if a: ext_in.append((a,val))
            else: unknown_inputs += 1
    u_out=[]; total_to_u=0
    for vo in vouts:
        a=addr_from_vout(vo); val=int(vo.get("value") or 0)
        if a in TARGET:
            u_out.append((a,val)); total_to_u += val
    if not u_in and not u_out:
        continue
    boundary_in=max(0,total_to_u-total_from_u)
    boundary_out=max(0,total_from_u-total_to_u)
    first = total_to_u>0 and total_from_u==0
    internal = total_to_u>0 and total_from_u>0
    ext_addrs=sorted(set(a for a,_ in ext_in))
    uin_addrs=sorted(set(a for a,_ in u_in)); uout_addrs=sorted(set(a for a,_ in u_out))
    row={
      "block_time_utc":iso(ts),"block_time_unix":ts or "","txid":txid,
      "total_to_universe_sats":total_to_u,"total_from_universe_sats":total_from_u,
      "boundary_net_inflow_sats":boundary_in,"boundary_net_outflow_sats":boundary_out,
      "first_touch_no_universe_inputs":first,"internal_or_mixed":internal,
      "external_input_addresses":";".join(ext_addrs),"universe_input_addresses":";".join(uin_addrs),
      "universe_output_addresses":";".join(uout_addrs),"unknown_input_count":unknown_inputs,
      "vin_count":len(vins),"vout_count":len(vouts),"fee_sats":int(tx.get("fee") or 0)
    }
    tx_rows.append(row)
    if first:
        first_touch.append(row.copy())
        if len(ext_addrs)>1:
            a0=ext_addrs[0]
            for a in ext_addrs[1:]: union(a0,a)
    if internal: internal_rows.append(row.copy())
    for a,val in u_out:
        s=addr_stats[a]; s["gross_received_sats"] += val
        if first:
            s["external_direct_received_sats"] += val; s["external_direct_tx_count"] += 1
        else:
            s["internal_received_sats"] += val; s["internal_receive_tx_count"] += 1
    for a,val in u_in:
        addr_stats[a]["gross_sent_input_sats"] += val
    for a in set(uin_addrs+uout_addrs):
        s=addr_stats[a]; s["tx_touch_count"] += 1
        if ts:
            s["first_seen"] = ts if s["first_seen"] is None else min(s["first_seen"],ts)
            s["last_seen"] = ts if s["last_seen"] is None else max(s["last_seen"],ts)

# Assign source-wallet entity IDs using common-input heuristic across first-touch transactions.
roots={}
for r in first_touch:
    addrs=[x for x in r["external_input_addresses"].split(";") if x]
    rr=sorted(set(find(a) for a in addrs))
    r["source_entity_roots"]=";".join(rr)
    for x in rr: roots.setdefault(x,None)
for n,root in enumerate(sorted(roots),1): roots[root]=f"SRC{n:05d}"
for r in first_touch:
    ids=[]
    for root in [x for x in r["source_entity_roots"].split(";") if x]: ids.append(roots[root])
    r["source_entity_ids"]=";".join(ids)

# Waves: first-touch txs sorted chronologically; a >14-day gap begins a new wave.
ft_sorted=sorted([r for r in first_touch if r["block_time_unix"]], key=lambda r:r["block_time_unix"])
wave=0; prev=None
for r in ft_sorted:
    if prev is None or r["block_time_unix"]-prev > 14*86400: wave += 1
    r["wave_id"]=f"W{wave:02d}"
    prev=r["block_time_unix"]
wave_by_tx={r["txid"]:r.get("wave_id","") for r in ft_sorted}
for r in tx_rows: r["wave_id"] = wave_by_tx.get(r["txid"],"")
for r in internal_rows: r["wave_id"] = ""

# summaries
wave_sum=defaultdict(lambda:{"tx_count":0,"boundary_sats":0,"source_entities":set(),"source_addresses":set(),"first":None,"last":None,"dest_addresses":set()})
for r in ft_sorted:
    w=wave_sum[r["wave_id"]]; w["tx_count"]+=1; w["boundary_sats"] += int(r["boundary_net_inflow_sats"])
    w["source_entities"].update(x for x in r["source_entity_ids"].split(";") if x)
    w["source_addresses"].update(x for x in r["external_input_addresses"].split(";") if x)
    w["dest_addresses"].update(x for x in r["universe_output_addresses"].split(";") if x)
    ts=int(r["block_time_unix"]); w["first"]=ts if w["first"] is None else min(w["first"],ts); w["last"]=ts if w["last"] is None else max(w["last"],ts)

# Write helpers
def write_csv(name, rows, fields):
    p=os.path.join(OUT,name)
    with open(p,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

addr_rows=[]
for a in sorted(TARGET):
    m=meta[a]; s=addr_stats[a]
    addr_rows.append({
      "address":a,"principal23":m["principal"],"supplement209":m["supplement"],"new8":m["new8"],
      "labels":";".join(m["labels"]),"clusters":";".join(m["clusters"]),
      "tx_touch_count":s["tx_touch_count"],"gross_received_sats":s["gross_received_sats"],
      "gross_sent_input_sats":s["gross_sent_input_sats"],"external_direct_received_sats":s["external_direct_received_sats"],
      "internal_received_sats":s["internal_received_sats"],"external_direct_tx_count":s["external_direct_tx_count"],
      "internal_receive_tx_count":s["internal_receive_tx_count"],"first_seen_utc":iso(s["first_seen"]),"last_seen_utc":iso(s["last_seen"])
    })

wave_rows=[]
for w in sorted(wave_sum):
    x=wave_sum[w]
    wave_rows.append({"wave_id":w,"first_utc":iso(x["first"]),"last_utc":iso(x["last"]),"first_touch_tx_count":x["tx_count"],
                      "source_entity_count_common_input_heuristic":len(x["source_entities"]),"unique_external_source_address_count":len(x["source_addresses"]),
                      "first_touch_attacker_address_count":len(x["dest_addresses"]),"boundary_inflow_sats":x["boundary_sats"]})

write_csv("address_summary.csv",addr_rows,list(addr_rows[0].keys()))
write_csv("transactions_touching_universe.csv",sorted(tx_rows,key=lambda r:(r["block_time_unix"] or 0,r["txid"])),list(tx_rows[0].keys()))
write_csv("first_touch.csv",ft_sorted,list(ft_sorted[0].keys()) if ft_sorted else [])
write_csv("internal_mixed.csv",sorted(internal_rows,key=lambda r:(r["block_time_unix"] or 0,r["txid"])),list(internal_rows[0].keys()) if internal_rows else [])
write_csv("waves.csv",wave_rows,list(wave_rows[0].keys()) if wave_rows else [])

summary={
 "universe_unique_addresses":len(TARGET),"principal23":len(data["principal23"]),"supplement209":len(data["supplement209"]),
 "principal_supplement_overlap":len(set(x["address"] for x in data["principal23"]) & set(x["address"] for x in data["supplement209"])),
 "new8_overlap_with_garren":len(set(x["address"] for x in data["new8"]) & (set(x["address"] for x in data["principal23"])|set(x["address"] for x in data["supplement209"]))),
 "unique_transactions_touching_universe":len(tx_rows),
 "garren_style_gross_received_sats":sum(x["gross_received_sats"] for x in addr_rows),
 "first_touch_direct_external_sats":sum(int(r["total_to_universe_sats"]) for r in first_touch),
 "network_boundary_net_inflow_sats":sum(int(r["boundary_net_inflow_sats"]) for r in tx_rows),
 "internal_mixed_transaction_count":len(internal_rows),"wave_count_14d_gap_rule":len(wave_rows),
 "method_note":"All numerical transaction data pulled fresh from Blockstream/mempool Esplora APIs. Address membership only comes from Garren principal/supplement address lists plus the 8 complaint-linked addresses. Boundary inflow = max(outputs to universe - inputs from universe,0) per transaction. First-touch = outputs to universe with zero universe inputs. Source entities are common-input heuristic, not proven persons."
}
with open(os.path.join(OUT,"summary.json"),"w",encoding="utf-8") as f: json.dump(summary,f,indent=2)
with open(os.path.join(OUT,"raw_transactions.json"),"w",encoding="utf-8") as f: json.dump(all_txs,f)
print(json.dumps(summary,indent=2))
