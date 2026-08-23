#!/usr/bin/env python3
import json, csv, time, urllib.request, os
from datetime import datetime, timezone
from collections import defaultdict

BASES = ["https://mempool.space/api", "https://blockstream.info/api"]
HERE = os.path.dirname(__file__)

def get_json(path, retries=6):
    last=None
    for attempt in range(retries):
        for base in BASES:
            url=base+path
            try:
                req=urllib.request.Request(url, headers={"User-Agent":"BTC-forensic-research/1.0"})
                with urllib.request.urlopen(req, timeout=45) as r:
                    return json.loads(r.read().decode())
            except Exception as e:
                last=e
        time.sleep(min(2**attempt, 20))
    raise RuntimeError(f"GET failed {path}: {last}")

with open(os.path.join(HERE,"addresses.json")) as f:
    cfg=json.load(f)
principal=set(cfg["garren_principal_23"])
cluster_rows=cfg["garren_cluster_209"]
cluster209={r["address"] for r in cluster_rows}
new8=set(cfg["new_complaint_8"])
known=principal|cluster209|new8
cluster_label={r["address"]:r["label"] for r in cluster_rows}
address_origin={}
for a in known:
    flags=[]
    if a in principal: flags.append("Garren principal")
    if a in cluster209: flags.append("Garren 209")
    if a in new8: flags.append("New complaint 8")
    address_origin[a]=" + ".join(flags)

def addr_txs(addr):
    out=[]; last=None; seen=set()
    while True:
        path=f"/address/{addr}/txs/chain" + (f"/{last}" if last else "")
        page=get_json(path)
        if not page: break
        for tx in page:
            if tx["txid"] not in seen:
                out.append(tx); seen.add(tx["txid"])
        if len(page)<25: break
        last=page[-1]["txid"]
        time.sleep(0.08)
    try:
        for tx in get_json(f"/address/{addr}/txs/mempool"):
            if tx["txid"] not in seen:
                out.append(tx); seen.add(tx["txid"])
    except Exception:
        pass
    return out

all_txs={}; address_stats={}; failures=[]
for i,a in enumerate(sorted(known),1):
    try:
        st=get_json(f"/address/{a}"); address_stats[a]=st
        txs=addr_txs(a)
        for tx in txs: all_txs[tx["txid"]]=tx
        print(f"[{i}/{len(known)}] {a} txs={len(txs)} unique_global={len(all_txs)}", flush=True)
        time.sleep(0.08)
    except Exception as e:
        failures.append((a,str(e))); print("FAIL",a,e,flush=True)

def vin_addr(v):
    p=v.get("prevout") or {}; return p.get("scriptpubkey_address")
def vout_addr(v): return v.get("scriptpubkey_address")
def block_time(tx): return (tx.get("status") or {}).get("block_time")

tx_rows=[]
addr_receipts=defaultdict(lambda: {"gross_sat":0,"external_sat":0,"internal_sat":0,"mixed_sat":0,"receipt_txs":set()})
external_rows=[]; internal_rows=[]; mixed_rows=[]
for txid,tx in all_txs.items():
    known_in_sat=0; unknown_in_sat=0; known_input_addrs=set(); unknown_input_addrs=set()
    for v in tx.get("vin",[]):
        p=v.get("prevout") or {}; a=p.get("scriptpubkey_address"); val=p.get("value") or 0
        if a:
            if a in known: known_in_sat += val; known_input_addrs.add(a)
            else: unknown_in_sat += val; unknown_input_addrs.add(a)
        else: unknown_in_sat += val
    known_outputs=[]; total_known_out=0
    for idx,v in enumerate(tx.get("vout",[])):
        a=vout_addr(v); val=v.get("value") or 0
        if a in known:
            known_outputs.append((a,idx,val)); total_known_out += val
            d=addr_receipts[a]; d["gross_sat"] += val; d["receipt_txs"].add(txid)
    if not known_outputs: continue
    if known_in_sat==0: flow_class="EXTERNAL_ONLY"
    elif unknown_in_sat==0: flow_class="ATTACKER_INTERNAL_ONLY"
    else: flow_class="MIXED_INPUTS"
    t=block_time(tx); dt=datetime.fromtimestamp(t,tz=timezone.utc).isoformat() if t else ""
    row={
        "txid":txid,"block_time_utc":dt,"flow_class":flow_class,
        "known_attacker_output_btc":total_known_out/1e8,
        "known_attacker_input_btc":known_in_sat/1e8,
        "external_unknown_input_btc":unknown_in_sat/1e8,
        "known_input_addresses":";".join(sorted(known_input_addrs)),
        "external_input_addresses":";".join(sorted(unknown_input_addrs)),
        "attacker_output_addresses":";".join(a for a,_,_ in known_outputs),
        "attacker_output_detail":";".join(f"{a}:{idx}:{val/1e8:.8f}" for a,idx,val in known_outputs),
    }
    tx_rows.append(row)
    if flow_class=="EXTERNAL_ONLY": external_rows.append(row)
    elif flow_class=="ATTACKER_INTERNAL_ONLY": internal_rows.append(row)
    else: mixed_rows.append(row)
    for a,idx,val in known_outputs:
        if flow_class=="EXTERNAL_ONLY": addr_receipts[a]["external_sat"] += val
        elif flow_class=="ATTACKER_INTERNAL_ONLY": addr_receipts[a]["internal_sat"] += val
        else: addr_receipts[a]["mixed_sat"] += val

ext_sorted=sorted([r for r in external_rows if r["block_time_utc"]], key=lambda x:x["block_time_utc"])
wave=0; prev=None
for r in ext_sorted:
    cur=datetime.fromisoformat(r["block_time_utc"])
    if prev is None or (cur-prev).total_seconds() > 14*86400: wave += 1
    r["wave"]=f"Wave {wave}"; prev=cur
for r in external_rows:
    srcs=[x for x in r["external_input_addresses"].split(";") if x]
    r["source_entity_id"]="TXSRC-"+r["txid"][:12]
    r["source_address_count"]=len(srcs)
    r["first_touch_attacker_count"]=len([x for x in r["attacker_output_addresses"].split(";") if x])

wave_summary=defaultdict(lambda: {"txs":0,"btc":0.0,"source_entities":set(),"source_addresses":set(),"attacker_addresses":set(),"start":None,"end":None})
for r in external_rows:
    if not r.get("wave"): continue
    w=wave_summary[r["wave"]]; w["txs"]+=1; w["btc"]+=r["known_attacker_output_btc"]; w["source_entities"].add(r["source_entity_id"])
    w["source_addresses"].update([x for x in r["external_input_addresses"].split(";") if x]); w["attacker_addresses"].update([x for x in r["attacker_output_addresses"].split(";") if x])
    d=r["block_time_utc"][:10]; w["start"]=d if w["start"] is None or d<w["start"] else w["start"]; w["end"]=d if w["end"] is None or d>w["end"] else w["end"]

os.makedirs(os.path.join(HERE,"out"),exist_ok=True)
def write_csv(name, rows, fields):
    with open(os.path.join(HERE,"out",name),"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})

tx_fields=["txid","block_time_utc","flow_class","known_attacker_output_btc","known_attacker_input_btc","external_unknown_input_btc","known_input_addresses","external_input_addresses","attacker_output_addresses","attacker_output_detail"]
write_csv("all_known_inbound_txs.csv",sorted(tx_rows,key=lambda r:r["block_time_utc"]),tx_fields)
ext_fields=["wave","block_time_utc","txid","source_entity_id","source_address_count","external_input_addresses","attacker_output_addresses","first_touch_attacker_count","known_attacker_output_btc","external_unknown_input_btc"]
write_csv("external_first_touch.csv",sorted(external_rows,key=lambda r:r["block_time_utc"]),ext_fields)
write_csv("internal_attacker_transfers.csv",sorted(internal_rows,key=lambda r:r["block_time_utc"]),tx_fields)
write_csv("mixed_input_transfers.csv",sorted(mixed_rows,key=lambda r:r["block_time_utc"]),tx_fields)

addr_rows=[]
for a in sorted(known):
    st=address_stats.get(a,{}); cs=st.get("chain_stats",{}); d=addr_receipts[a]
    addr_rows.append({
        "address":a,"origin":address_origin[a],"cluster":cluster_label.get(a,""),"chain_tx_count":cs.get("tx_count",""),
        "chain_funded_btc":(cs.get("funded_txo_sum",0) or 0)/1e8,"chain_spent_btc":(cs.get("spent_txo_sum",0) or 0)/1e8,
        "reconstructed_gross_btc":d["gross_sat"]/1e8,"external_first_touch_btc":d["external_sat"]/1e8,
        "attacker_internal_received_btc":d["internal_sat"]/1e8,"mixed_received_btc":d["mixed_sat"]/1e8,"receipt_tx_count":len(d["receipt_txs"]),
        "is_garren_principal":a in principal,"is_garren_209":a in cluster209,"is_new8":a in new8,
    })
write_csv("address_summary.csv",addr_rows,list(addr_rows[0].keys()))
wave_rows=[]
for w in sorted(wave_summary,key=lambda x:int(x.split()[-1])):
    d=wave_summary[w]
    wave_rows.append({"wave":w,"start_date":d["start"],"end_date":d["end"],"external_theft_candidate_txs":d["txs"],"source_entity_candidates":len(d["source_entities"]),"unique_external_source_addresses":len(d["source_addresses"]),"first_touch_attacker_addresses":len(d["attacker_addresses"]),"unique_external_btc":round(d["btc"],8)})
write_csv("wave_summary.csv",wave_rows,list(wave_rows[0].keys()) if wave_rows else ["wave"])

gross=sum(r["known_attacker_output_btc"] for r in tx_rows); external=sum(r["known_attacker_output_btc"] for r in external_rows); internal=sum(r["known_attacker_output_btc"] for r in internal_rows); mixed=sum(r["known_attacker_output_btc"] for r in mixed_rows)
summary={
    "known_unique_addresses":len(known),"garren_principal_23":len(principal),"garren_209":len(cluster209),"new8":len(new8),"principal_209_overlap":len(principal & cluster209),"all_unique_txids_touching_known_addresses":len(all_txs),
    "gross_receipts_reconstructed_btc":round(gross,8),"external_only_first_touch_btc":round(external,8),"attacker_internal_receipts_btc":round(internal,8),"mixed_input_receipts_btc":round(mixed,8),"external_only_tx_count":len(external_rows),"attacker_internal_tx_count":len(internal_rows),"mixed_input_tx_count":len(mixed_rows),"failures":failures,
    "method":"Fresh Esplora pull from mempool.space with blockstream.info fallback. External-only first-touch = transaction has outputs to known attacker set and no known attacker address among inputs. Internal-only = all identified input addresses are in known attacker set. Mixed = both known and external inputs; excluded from conservative first-touch total.",
    "wave_rule":"External-only transactions grouped chronologically; a new wave begins after a >14 day gap."
}
with open(os.path.join(HERE,"out","summary.json"),"w") as f: json.dump(summary,f,indent=2)
with open(os.path.join(HERE,"out","failures.csv"),"w",newline="") as f:
    w=csv.writer(f); w.writerow(["address","error"]); w.writerows(failures)
print(json.dumps(summary,indent=2))
