#!/usr/bin/env python3
import json,time,urllib.request
from collections import defaultdict
from pathlib import Path
from datetime import datetime,timezone

BASES=[('mempool','https://mempool.space/api'),('blockstream','https://blockstream.info/api')]
TARGET='1HbVpndSdSbbNk1YdzVa3B4Aiw5R1Kxqx1'
SOURCE='1gpG8WogRxYwhnfaS4ELMnfT4UGXieRpe'
THEFT_TX='745858ab633a5d67744f0774fdc232143ca02a44707e86f4e4a9cd801e830307'
REPORTED_DOWNSTREAM=['1FnWC3Tt2eMnKENi7KeZT3GRcjxcnE3jdz','1CsRsAaGgWXXyRMVXhcRx3wiVmGFaMCNJt']
OUT=Path('btc_forensic/new2020_address_out'); OUT.mkdir(parents=True,exist_ok=True)

def get(path):
    errs=[]
    for name,base in BASES:
        for n in range(3):
            try:
                req=urllib.request.Request(base+path,headers={'User-Agent':'BTC-forensic-research/3.0'})
                with urllib.request.urlopen(req,timeout=25) as r:return json.loads(r.read().decode()),name
            except Exception as e:
                errs.append(f'{name}:{e}'); time.sleep(1+n)
    raise RuntimeError(' | '.join(errs))

def history(addr):
    out=[]; seen=set(); last=None
    while True:
        p=f'/address/{addr}/txs/chain'+(f'/{last}' if last else '')
        page,src=get(p)
        if not page: break
        for tx in page:
            if tx['txid'] not in seen: out.append(tx); seen.add(tx['txid'])
        if len(page)<25:break
        last=page[-1]['txid']
    return out

def addrs_in(tx,which):
    if which=='in': return [((v.get('prevout') or {}).get('scriptpubkey_address')) for v in tx.get('vin',[]) if (v.get('prevout') or {}).get('scriptpubkey_address')]
    return [v.get('scriptpubkey_address') for v in tx.get('vout',[]) if v.get('scriptpubkey_address')]

def sat_to_btc(x): return x/1e8

def tstamp(tx):
    t=(tx.get('status') or {}).get('block_time')
    return datetime.fromtimestamp(t,tz=timezone.utc).isoformat() if t else None

cfg=json.load(open('btc_forensic/addresses.json',encoding='utf-8'))
known=set(cfg['garren_principal_23'])|{r['address'] for r in cfg['garren_cluster_209']}|set(cfg['new_complaint_8'])

addresses=[TARGET,SOURCE]+REPORTED_DOWNSTREAM
summary={'target':TARGET,'source':SOURCE,'theft_txid':THEFT_TX,'reported_downstream':REPORTED_DOWNSTREAM,'known_227_overlap':{},'addresses':{},'transactions':[],'co_spend_neighbors':{},'direct_known227_links':[]}
alltx={}
for a in addresses:
    st,_=get('/address/'+a)
    txs=history(a)
    for tx in txs: alltx[tx['txid']]=tx
    cs=st.get('chain_stats',{})
    summary['addresses'][a]={
      'tx_count':cs.get('tx_count',0),
      'funded_btc':sat_to_btc(cs.get('funded_txo_sum',0)),
      'spent_btc':sat_to_btc(cs.get('spent_txo_sum',0)),
      'balance_btc':sat_to_btc(cs.get('funded_txo_sum',0)-cs.get('spent_txo_sum',0)),
      'first_tx':min([tstamp(x) for x in txs if tstamp(x)] or [None]),
      'last_tx':max([tstamp(x) for x in txs if tstamp(x)] or [None]),
      'known_227':a in known,
    }
    summary['known_227_overlap'][a]=a in known

# exact theft tx fresh fetch
theft,_=get('/tx/'+THEFT_TX); alltx[THEFT_TX]=theft
summary['theft_transaction']={
  'date_utc':tstamp(theft),
  'inputs':[{'address':(v.get('prevout') or {}).get('scriptpubkey_address'),'btc':sat_to_btc((v.get('prevout') or {}).get('value',0))} for v in theft.get('vin',[])],
  'outputs':[{'address':v.get('scriptpubkey_address'),'btc':sat_to_btc(v.get('value',0))} for v in theft.get('vout',[])],
  'source_is_input':SOURCE in addrs_in(theft,'in'),
  'target_is_output':TARGET in addrs_in(theft,'out'),
  'btc_to_target':sat_to_btc(sum(v.get('value',0) for v in theft.get('vout',[]) if v.get('scriptpubkey_address')==TARGET)),
}

# analyze all target-related txs, co-spends, known-227 links and immediate destinations
for a in [TARGET]+REPORTED_DOWNSTREAM:
    co=set(); dest=defaultdict(int)
    for tx in history(a):
        ins=addrs_in(tx,'in'); outs=addrs_in(tx,'out')
        if a in ins:
            co.update(x for x in ins if x!=a)
            for v in tx.get('vout',[]):
                x=v.get('scriptpubkey_address')
                if x and x!=a: dest[x]+=v.get('value',0)
        overlap=(set(ins)|set(outs))&known
        if overlap:
            summary['direct_known227_links'].append({'focus_address':a,'txid':tx['txid'],'date_utc':tstamp(tx),'known_addresses':sorted(overlap),'inputs':ins,'outputs':outs})
    summary['co_spend_neighbors'][a]=sorted(co)
    summary['addresses'][a]['top_spend_destinations']=[{'address':x,'btc':sat_to_btc(v),'known_227':x in known} for x,v in sorted(dest.items(),key=lambda kv:-kv[1])[:25]]

# Fetch co-spend neighbors and check overlap, but do not recursively explode
neighbors=sorted(set(x for xs in summary['co_spend_neighbors'].values() for x in xs))
summary['co_spend_neighbor_count']=len(neighbors)
summary['co_spend_known227_overlap']=sorted(set(neighbors)&known)

# Key tx summaries around target
for tx in sorted(alltx.values(),key=lambda x:((x.get('status') or {}).get('block_time') or 0,x['txid'])):
    ins=addrs_in(tx,'in'); outs=addrs_in(tx,'out')
    if TARGET in ins or TARGET in outs or tx['txid']==THEFT_TX:
        summary['transactions'].append({'txid':tx['txid'],'date_utc':tstamp(tx),'inputs':ins,'outputs':outs,'target_in_btc':sat_to_btc(sum((v.get('prevout') or {}).get('value',0) for v in tx.get('vin',[]) if (v.get('prevout') or {}).get('scriptpubkey_address')==TARGET)),'target_out_btc':sat_to_btc(sum(v.get('value',0) for v in tx.get('vout',[]) if v.get('scriptpubkey_address')==TARGET))})

# cross-check exact address stats from both public explorers
summary['crosscheck']={}
for a in addresses:
    per={}
    for name,base in BASES:
        req=urllib.request.Request(base+'/address/'+a,headers={'User-Agent':'BTC-forensic-research/3.0'})
        with urllib.request.urlopen(req,timeout=25) as r: per[name]=json.loads(r.read().decode())['chain_stats']
    summary['crosscheck'][a]={'match':per['mempool']==per['blockstream'],'mempool':per['mempool'],'blockstream':per['blockstream']}

json.dump(summary,open(OUT/'investigation.json','w',encoding='utf-8'),indent=2)
print(json.dumps(summary,indent=2))
