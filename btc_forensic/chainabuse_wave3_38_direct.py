#!/usr/bin/env python3
from __future__ import annotations
import base64,csv,json,re,time,sys
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path
import requests

ENDPOINT="https://chainabuse.com/api/graphql-proxy"
START=datetime(2021,1,1,tzinfo=timezone.utc)
END=datetime(2022,1,1,tzinfo=timezone.utc)
OUT=Path("btc_forensic/chainabuse_wave3_38_out"); OUT.mkdir(parents=True,exist_ok=True)
TARGETS=set(['3D6NHEMGuny6EDFF1tD12jcaYG3158TPUw', 'bc1q0glfvq9rjwpvyzay3569pz0hmyptrxyhdayn3d', 'bc1q233ll74vfm08t2jzctv6pdlv0xlzut68puh0yk', 'bc1q2926h5mcw8xvr88r39qua57xhkkyu37zmatjk6', 'bc1q43ur7xrqdtfwsgd2lzsm8rundn47mu9mgqdwww', 'bc1q686qnmud5dt3wpea2qguz3u7q5gqqmheynu60l', 'bc1q6hv46f62waddp2qt62pt46zkgs8lpcf8ewrq7p', 'bc1q7ju5ts2nclm2nmmwfw4vv9lw223exexkcqzmk7', 'bc1q7kv2ulvjysj6utrh388s004pr8fx3tcs0j0whj', 'bc1q92yds887lcv9r6dwxkhh49eywla4ta7fn2a3u4', 'bc1qdpg77c68zf2gqq8k36mu2q6xvdv427gs2vgmyd', 'bc1qdspl8qlttvkfrj2k6umhfkad3k89rp969stnks', 'bc1qejaycff9zetp9q3m08w4a3hmfaaqfkenaqfjtw', 'bc1qew6qczw2ddrsqe3zffwlmwaqvl0dja5rvmd822', 'bc1qez4ysudgcsxz774ztc35v3qs2duwhggzgxw4kt', 'bc1qf4mxj2k55hsuurckwz8tse0l3xupl4jx2ytmp2', 'bc1qg59rls4s8p0lcntpujt9fuparrfvhs2j8rct78', 'bc1qgg5mfxx3pnpq2wk4l73a9dj2xv0tn9j9kv46k9', 'bc1qhp9ezalqpurxanhaf9lm0939znwml5u6rtu5x6', 'bc1qkyg9hdsgjre9p9hve208wwqmmghn3364fj0kjf', 'bc1qkzjv5a6xhsc9jru3yzakrv3gyg0fz56t820dha', 'bc1qld4zqhppecfgze50qzj887nc5flt6mhgmvgy3v', 'bc1qlkcz379a3pyf4jl3gr7539hkqnl3my2nmkcsrj', 'bc1qlpw5eqklds8809wfxr0g3rsrcklljxzgkmcs95', 'bc1qnmnk5h39m9jnxelgk4jw85qf4xq4ruwe5tde8l', 'bc1qpr45hgd8a8qt03v650e0u2n78rmuvffa60ksxl', 'bc1qqvwqjr5vvvtsr477h4ufytnmfwrp54w69092q4', 'bc1qrx7rt52tma3utg5q23rrssmrfpal3l2sxej3t0', 'bc1qscpedw6ny3y5wtcemcv5n378naudekms236m6l', 'bc1qsrvrlc83ugtj5alycp047ekn78xjym434evdnm', 'bc1qu2aahulet7xw6tz4585qjvp3l8pq70qm7rgxhv', 'bc1qu7v26pl762pz5ud6gq6veypzp5kccxfvlsl738', 'bc1qv30m62h327rt8cnu4njtkna3zn5xq6p8r9x68s', 'bc1qwtuk8tylakuem4daqmgv0lue46qszfa0n7rp3h', 'bc1qx8yu9snl56lu4pjy2uejue8v2x8ec6d4pa73ca', 'bc1qxgmlwmxf5vvpgwwaflluu6c3hst3csmwevpamt', 'bc1qxkx3ftqnmhzdxckphg6e3ejfu6ufpukc3z7394', 'bc1qyadq6tmpz059qp9e6y6z2mtkzsqypw72x2apes'])
BC_RE=re.compile(r'\bblockchain\.com\b|\bblockchain\.info\b|\bwallet\.blockchain\b|\bblockchain\s+(?:support|insider|account|wallet|app|website|exchange)\b|\bmy\s+blockchain\b|\bon\s+blockchain\b|\bblokchain\b|\bblock\s*chain\s+(?:account|wallet|balance|app|website|exchange)\b',re.I)
TWOFA_RE=re.compile(r'\b2fa\b|two[- ]?factor|two[- ]?step|otp|one[- ]?time|verification code|security code|authenticator|\bsms\b|text message|no code|didn.?t receive.*code|without.*code|no notification|no alert|no confirmation',re.I)
QUERY=r"""query GetReports($input: ReportsInput, $after: String, $first: Float) { reports(input:$input, after:$after, first:$first) { pageInfo { hasNextPage endCursor } edges { node { id createdAt description lexicalSerializedDescription source scamCategory categoryDescription addresses { address chain domain label } } } totalCount } }"""

def cursor(i): return base64.b64encode(f"arrayconnection:{i}".encode()).decode()
def pdt(v):
    if not v:return None
    s=v[:-1]+"+00:00" if v.endswith("Z") else v
    try:d=datetime.fromisoformat(s)
    except:return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
def text(n): return "\n".join(str(n.get(k) or "") for k in ("description","lexicalSerializedDescription","categoryDescription","scamCategory"))
def node_addrs(n):
    out=set()
    for a in n.get("addresses") or []:
        x=(a or {}).get("address")
        if isinstance(x,str): out.add(x.strip())
    t=text(n)
    for a in TARGETS:
        if a in t: out.add(a)
    return out
def sess():
    s=requests.Session()
    s.headers.update({"Accept":"application/json","Content-Type":"application/json","Origin":"https://chainabuse.com","Referer":"https://chainabuse.com/","User-Agent":"Mozilla/5.0 Direct-Wave3-38-Research/1.0"})
    return s
def gql(s,first=1,after=None):
    payload={"operationName":"GetReports","variables":{"input":{"chains":[],"scamCategories":[],"orderBy":{"field":"CREATED_AT","direction":"DESC"}},"first":first},"query":QUERY}
    if after is not None: payload["variables"]["after"]=after
    for k in range(6):
        r=s.post(ENDPOINT,json=payload,timeout=60)
        if r.status_code==429:
            time.sleep(2**k); continue
        r.raise_for_status(); o=r.json()
        if o.get("errors"): raise RuntimeError(o["errors"])
        return o["data"]["reports"]
    raise RuntimeError("rate limited")
def node_at(s,i):
    e=gql(s,1,cursor(i-1)).get("edges") or []
    if not e: raise RuntimeError(f"no node at {i}")
    return e[0]["node"]
def first_older(s,target,total):
    lo,hi=0,total
    while lo<hi:
        mid=(lo+hi)//2; d=pdt(node_at(s,mid).get("createdAt"))
        if d < target: hi=mid
        else: lo=mid+1
        time.sleep(.03)
    return lo

def main():
    s=sess()
    total=int(gql(s,1,cursor(-1))["totalCount"])
    start=first_older(s,END,total); end=first_older(s,START,total)
    print(f"2021 direct Chainabuse slice {start}:{end} count={end-start}",file=sys.stderr)
    matched=defaultdict(dict); pos=start; scanned=0
    raw=OUT/"matched_reports.jsonl"; raw.write_text("",encoding="utf-8")
    while pos<end:
        n=min(100,end-pos)
        rep=gql(s,n,cursor(pos-1)); edges=rep.get("edges") or []
        if not edges: break
        with raw.open("a",encoding="utf-8") as f:
            for e in edges:
                nd=e["node"]; d=pdt(nd.get("createdAt"))
                if not d or not (START<=d<END): continue
                scanned += 1
                for a in (node_addrs(nd) & TARGETS):
                    rid=str(nd.get("id") or json.dumps(nd,sort_keys=True))
                    matched[a][rid]=nd
                    f.write(json.dumps({"target":a,"report":nd},ensure_ascii=False)+"\n")
        pos += len(edges)
        if scanned % 1000 < 100: print(f"scanned={scanned}",file=sys.stderr)
        time.sleep(.03)
    rows=[]
    for a in sorted(TARGETS):
        reps=list(matched.get(a,{}).values())
        dates=[pdt(r.get("createdAt")) for r in reps if pdt(r.get("createdAt"))]
        bc=sum(bool(BC_RE.search(text(r))) for r in reps)
        fa=sum(bool(TWOFA_RE.search(text(r))) for r in reps)
        rows.append({
            "address":a,
            "reports_2021":len(reps),
            "blockchain_mentions":bc,
            "2fa_or_confirmation_mentions":fa,
            "first_report":min(dates).date().isoformat() if dates else "",
            "last_report":max(dates).date().isoformat() if dates else "",
        })
    with (OUT/"wave3_38_direct_results.csv").open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    summary={
        "source":"Direct fresh pull from https://chainabuse.com/api/graphql-proxy",
        "window":"2021-01-01 through 2021-12-31",
        "target_addresses":len(TARGETS),
        "global_2021_reports_scanned":scanned,
        "targets_with_any_report":sum(r["reports_2021"]>0 for r in rows),
        "total_reports_on_targets":sum(r["reports_2021"] for r in rows),
        "targets_with_blockchain_mention":sum(r["blockchain_mentions"]>0 for r in rows),
        "total_blockchain_mentions":sum(r["blockchain_mentions"] for r in rows),
        "targets_with_2fa_or_confirmation_mention":sum(r["2fa_or_confirmation_mentions"]>0 for r in rows),
    }
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2))
if __name__=="__main__": main()
