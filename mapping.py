"""Map authorized historical observations; no network or recursive discovery."""
import argparse
from collections import defaultdict
import csv
from datetime import date
import ipaddress
import itertools
import json
from pathlib import Path
import re

def domain(value):
    value=value.strip().lower().rstrip('.')
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',v) for v in value.split('.')):
        raise ValueError('invalid domain')
    return value

def load_scope(path):
    scope=json.loads(path.read_text(encoding='utf-8'))
    if not scope.get('authorization_note') or not isinstance(scope.get('allowed_domains'),list):
        raise ValueError('authorization note and exact allowed_domains required')
    if scope.get('dataset_kind') not in ('synthetic','authorized_historical'):
        raise ValueError('unsupported dataset kind')
    scope['allowed_domains']=[domain(x) for x in scope['allowed_domains']]
    if not scope['allowed_domains']: raise ValueError('empty scope')
    return scope

def validate(rows,scope):
    allowed=set(scope['allowed_domains']); result=[]; seen=set()
    for item in rows:
        row={k:v.strip() for k,v in item.items() if k is not None and isinstance(v,str)}
        required=('id','domain','kind','value','first_seen','last_seen','source')
        if any(not row.get(k) for k in required): raise ValueError('missing observation field')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',row['id']) or row['id'] in seen:
            raise ValueError('invalid or duplicate observation ID')
        seen.add(row['id']); row['domain']=domain(row['domain'])
        if row['domain'] not in allowed: raise ValueError('out-of-scope domain: '+row['domain'])
        first,last=date.fromisoformat(row['first_seen']),date.fromisoformat(row['last_seen'])
        if first>last: raise ValueError('reversed interval')
        row['first_seen'],row['last_seen']=first.isoformat(),last.isoformat()
        if row['kind']=='dns_a':
            ip=ipaddress.IPv4Address(row['value']); row['value']=str(ip)
            if scope['dataset_kind']=='synthetic' and not any(ip in ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')):
                raise ValueError('synthetic IP must use TEST-NET')
        elif row['kind']=='certificate_sha256':
            if not re.fullmatch(r'[0-9a-fA-F]{64}',row['value']): raise ValueError('invalid certificate SHA-256')
            row['value']=row['value'].lower()
        else: raise ValueError('unsupported observation kind')
        if scope['dataset_kind']=='synthetic' and not row['domain'].endswith('.test'):
            raise ValueError('synthetic domains must end with .test')
        result.append({k:row[k] for k in required})
    return sorted(result,key=lambda r:r['id'])

def build_graph(rows,scope):
    rows=validate(rows,scope)
    groups=defaultdict(list); observations=[]; nodes=set()
    for row in rows:
        resource=row['kind']+':'+row['value']
        node='domain:'+row['domain']; nodes.update([node,resource])
        observations.append({'from':node,'to':resource,'relation':row['kind'],**row})
        groups[(row['kind'],row['value'])].append(row)
    relationships=[]
    for (kind,value),items in sorted(groups.items()):
        for a,b in itertools.combinations(items,2):
            if a['domain']==b['domain']: continue
            first=max(a['first_seen'],b['first_seen']); last=min(a['last_seen'],b['last_seen'])
            if first>last: continue
            left,right=sorted([a['domain'],b['domain']])
            relationships.append({'from':left,'to':right,'relation':'shared_ip' if kind=='dns_a' else 'shared_certificate',
                'value':value,'overlap_start':first,'overlap_end':last,'evidence_ids':sorted([a['id'],b['id']]),
                'assessment':'lead_only_not_attribution'})
    relationships.sort(key=lambda x:(x['from'],x['to'],x['relation'],x['evidence_ids']))
    return {'schema_version':1,'dataset_kind':scope['dataset_kind'],'nodes':sorted(nodes),
        'observations':observations,'relationships':relationships,
        'warning':'Intervals are observation bounds, not proof of continuous use. Shared infrastructure is not common ownership.'}

def to_dot(graph):
    # json.dumps quotes and escapes imported strings; never execute Graphviz here.
    q=lambda x:json.dumps(x,ensure_ascii=True)
    lines=['graph infrastructure {','  rankdir=LR;',
        '  graph [label="SYNTHETIC OBSERVATIONS — not ownership or attribution", labelloc=t, fontname="Arial", pad=0.3];',
        '  node [shape=box, style="rounded,filled", fontname="Arial", fillcolor="#edf4fc"];',
        '  edge [fontname="Arial", fontsize=10, color="#60758a"];']
    for n in graph['nodes']:
        label=n
        if n.startswith('certificate_sha256:'):
            label='certificate SHA-256\n'+n.split(':',1)[1][:12]+'...'+n[-8:]
        lines.append('  '+q(n)+' [label='+q(label)+'];')
    for o in graph['observations']:
        label=o['id']+' '+o['first_seen']+'..'+o['last_seen']
        lines.append('  '+q(o['from'])+' -- '+q(o['to'])+' [label='+q(label)+'];')
    return '\n'.join(lines+['}'])+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,default=Path('data/observations.csv'))
    p.add_argument('--scope',type=Path,default=Path('data/scope.json'))
    p.add_argument('--output',type=Path,default=Path('local/result'))
    a=p.parse_args()
    try:
        if a.input.stat().st_size>1_000_000: raise ValueError('input exceeds 1 MB')
        scope=load_scope(a.scope)
        with a.input.open(encoding='utf-8',newline='') as f: rows=list(csv.DictReader(f))
        if not 1<=len(rows)<=1000: raise ValueError('expected 1..1000 observations')
        graph=build_graph(rows,scope)
        a.output.mkdir(parents=True,exist_ok=True)
        (a.output/'graph.json').write_text(json.dumps(graph,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (a.output/'graph.dot').write_text(to_dot(graph),encoding='utf-8')
        print(json.dumps({'observations':len(rows),'relationships':len(graph['relationships']),'output':str(a.output)}))
    except (ValueError,OSError) as exc: p.error(str(exc))

if __name__=='__main__': main()
