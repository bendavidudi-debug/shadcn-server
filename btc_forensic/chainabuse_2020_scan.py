#!/usr/bin/env python3
from __future__ import annotations
import base64, csv, json, re, time, sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
import requests

ENDPOINT='https://chainabuse.com/api/graphql-proxy'
WINDOW_START=datetime(2020,6,1,tzinfo=timezone.utc)
WINDOW_END=datetime(2021,1,1,tzinfo=timezone.utc)
OUT=Path('btc_forensic/chainabuse_2020_out'); OUT.mkdir(parents=True,exist_ok=True)
BTC_RE=re.compile(r'(?<![A-Za-z0-9])((?:bc1)[ac-hj-np-z02-9]{11,71}|(?:[13])[a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])')
BC_RE=re.compile(r'\bblockchain\.com\b|\bblockchain\.info\b|\bwallet\.blockchain\b|\bblockchain\s+(?:support|insider|account|wallet|app|website|exchange)\b|\bmy\s+blockchain\b|\bon\s+blockchain\b|\bblokchain\b|\bblock\s*chain\s+(?:account|wallet|balance|app|website|exchange)\b',re.I)
BC_POSSIBLE_RE=re.compile(r'(?<![A-Za-z0-9])BC(?![A-Za-z0-9])',re.I)
OTHER_RE=re.compile(r'\bcoinbase\b|\bbinance\b|\bkraken\b|\bbitstamp\b|\bgemini\b|\bcrypto\.com\b|\bkucoin\b|\bbittrex\b|\bhuobi\b|\bokx\b|\bokex\b|\bbitfinex\b|\bexodus\b|\belectrum\b|\bmetamask\b|\btrust\s*wallet\b|\bbitpay\b|\bluno\b|\bcoinjar\b|\bbitgo\b|\bmycelium\b|\bcoinpayments\b|\bcoinmama\b|\bpaxful\b|\blocalbitcoins\b',re.I)
QUERY=r'''query GetReports($input: ReportsInput, $after: String, $first: Float) { reports(input:$input, after:$after, first:$first) { pageInfo { hasNextPage endCursor } edges { node { id createdAt description lexicalSerializedDescription source scamCategory categoryDescription addresses { address chain domain label } } } totalCount } }'''

def cursor(i:int)->str: return base64.b64encode(f'arrayconnection:{i}'.encode()).decode()
def pdt(v):
    if not v:return None
    s=v[:-1]+'+00:00' if v.endswith('Z') else v
    try:d=datetime.fromisoformat(s)
    except:return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
def text(n):
    return '\n'.join(str(n.get(k) or '') for k in ('description','lexicalSerializedDescription','categoryDescription','scamCategory'))
def addrs(n):
    out=set()
    for a in n.get('addresses') or []:
        x=(a or {}).get('address')
        if isinstance(x,str) and BTC_RE.fullmatch(x.strip()):out.add(x.strip())
    out.update(m.group(1) for m in BTC_RE.finditer(text(n)))
    return out
def cls(n):
    t=text(n)
    if OTHER_RE.search(t):return 'other'
    if BC_RE.search(t):return 'blockchain'
    return 'none'

def session():
    s=requests.Session(); s.headers.update({'Accept':'application/json','Content-Type':'application/json','Origin':'https://chainabuse.com','Referer':'https://chainabuse.com/','User-Agent':'Mozilla/5.0 Chainabuse-2020-Research/1.0'}); return s

def gql(s,first=1,after=None):
    payload={'operationName':'GetReports','variables':{'input':{'chains':[],'scamCategories':[],'orderBy':{'field':'CREATED_AT','direction':'DESC'}},'first':first},'query':QUERY}
    if after is not None:payload['variables']['after']=after
    for attempt in range(5):
        r=s.post(ENDPOINT,json=payload,timeout=45)
        if r.status_code==429: time.sleep(2**attempt); continue
        r.raise_for_status(); o=r.json()
        if o.get('errors'): raise RuntimeError(o['errors'])
        return o['data']['reports']
    raise RuntimeError('rate limited after retries')

def node_at(s,i):
    e=gql(s,1,cursor(i-1)).get('edges') or []
    if not e:raise RuntimeError(f'no node at {i}')
    return e[0]['node']
def first_older(s,target,total):
    lo,hi=0,total
    while lo<hi:
        mid=(lo+hi)//2; d=pdt(node_at(s,mid).get('createdAt'))
        print('binary',mid,d,file=sys.stderr)
        if d<target:hi=mid
        else:lo=mid+1
        time.sleep(.05)
    return lo

def main():
    cfg=json.load(open('btc_forensic/addresses.json',encoding='utf-8'))
    known=set(cfg['garren_principal_23'])|{r['address'] for r in cfg['garren_cluster_209']}|set(cfg['new_complaint_8'])
    s=session(); first=gql(s,1,cursor(-1)); total=int(first['totalCount'])
    start=first_older(s,WINDOW_END,total); end=first_older(s,WINDOW_START,total)
    if end<=start:raise RuntimeError('invalid date slice')
    print(f'2020 slice {start}:{end} = {end-start}',file=sys.stderr)
    nodes=[]; pos=start
    raw=OUT/'chainabuse_2020_raw_reports.jsonl'; raw.write_text('',encoding='utf-8')
    while pos<end:
        n=min(100,end-pos); rep=gql(s,n,cursor(pos-1)); edges=rep.get('edges') or []
        if not edges:break
        batch=[]
        for e in edges:
            nd=e['node']; d=pdt(nd.get('createdAt'))
            if d and WINDOW_START<=d<WINDOW_END:batch.append(nd)
        with raw.open('a',encoding='utf-8') as f:
            for nd in batch:f.write(json.dumps(nd,ensure_ascii=False)+'\n')
        nodes.extend(batch); pos+=len(edges); print(f'fetch {pos-start}/{end-start}',file=sys.stderr); time.sleep(.05)
    per=defaultdict(dict)
    for n in nodes:
        rid=str(n.get('id') or json.dumps(n,sort_keys=True)); d=pdt(n.get('createdAt')); c=cls(n); possible=bool(BC_POSSIBLE_RE.search(text(n))) and c!='blockchain'
        for a in addrs(n): per[a][rid]=(d,c,possible,n)
    rows=[]
    for a,reps in per.items():
        vals=list(reps.values()); cc=Counter(v[1] for v in vals); dates=[v[0] for v in vals if v[0]]; possible=sum(v[2] for v in vals)
        rows.append({'address':a,'window_reports':len(vals),'blockchain_reports':cc['blockchain'],'bc_possible_reports':possible,'other_platform_reports':cc['other'],'no_platform_reports':cc['none'],'first_report_date':min(dates).date().isoformat() if dates else '','last_report_date':max(dates).date().isoformat() if dates else '','known_attacker_227':'Yes' if a in known else 'No','address_type':'bc1' if a.startswith('bc1') else 'legacy','strict_pass':'Yes' if len(vals)>=5 and cc['blockchain']>=2 and cc['other']==0 else 'No'})
    rows.sort(key=lambda r:(-r['blockchain_reports'],-r['window_reports'],r['address']))
    fields=list(rows[0].keys()) if rows else ['address']
    def write(name,subset):
        with (OUT/name).open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(subset)
    write('chainabuse_2020_all_candidates.csv',rows)
    write('chainabuse_2020_blockchain_mentions.csv',[r for r in rows if r['blockchain_reports']>0])
    write('chainabuse_2020_strict_matches.csv',[r for r in rows if r['strict_pass']=='Yes'])
    write('chainabuse_2020_over_10_total.csv',[r for r in rows if r['window_reports']>10])
    write('chainabuse_2020_known_227.csv',[r for r in rows if r['known_attacker_227']=='Yes'])
    summary={'window':'2020-06-01 through 2020-12-31','global_reports_downloaded':len(nodes),'unique_btc_candidates':len(rows),'strict_blockchain_mentions_addresses':sum(r['blockchain_reports']>0 for r in rows),'strict_matches':sum(r['strict_pass']=='Yes' for r in rows),'known_227_with_reports':sum(r['known_attacker_227']=='Yes' for r in rows),'legacy_candidates':sum(r['address_type']=='legacy' for r in rows),'bc1_candidates':sum(r['address_type']=='bc1' for r in rows)}
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))
if __name__=='__main__': main()
