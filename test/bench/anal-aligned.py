#!/usr/bin/env python3
import csv
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
out = root / 'results'
out.mkdir(exist_ok=True)
variants = ['baseline', 'previous', 'radare2']
src = root / 'radare2'
fixtures = src / 'test/bins'
metadata = {'platform': list(os.uname()), 'compiler': subprocess.check_output(['gcc','--version'],text=True),
            'fixtures': subprocess.check_output(['git','rev-parse','HEAD'],cwd=fixtures,text=True).strip(),
            'variants': {v: subprocess.check_output(['git','rev-parse','HEAD'],cwd=root/v,text=True).strip() for v in variants},
            'candidate_diff_sha256': hashlib.sha256(subprocess.check_output(['git','diff','HEAD'],cwd=src)).hexdigest()}
(out/'aligned-environment.json').write_text(json.dumps(metadata,indent=2)+'\n')

def env(v):
    prefix=root/v/'_install'
    return dict(os.environ,PATH=str(prefix/'bin')+os.pathsep+os.environ['PATH'],
                LD_LIBRARY_PATH=str(prefix/'lib'),R2_NOPLUGINS='1',
                XDG_DATA_HOME=str(out/'data'),XDG_CACHE_HOME=str(out/'cache'))

for v in variants:
    checkout=root/v; prefix=checkout/'_install'
    libs=['-l'+p.name[3:-3] for p in sorted((prefix/'lib').glob('libr_*.so'))]
    for name in ['anal-layout','anal-bb-lookup','anal-bb-storage']:
        subprocess.run(['gcc','-O2','-DBB_ORDER_CACHE='+str(int(v!='baseline')),
                        '-I'+str(checkout/'libr/include'),'-I'+str(checkout/'subprojects/sdb/include'),
                        src/'test/bench'/f'{name}.c','-o',out/f'{v}-{name}',
                        '-L'+str(prefix/'lib'),'-Wl,-rpath,'+str(prefix/'lib'),*libs,'-lm','-ldl'],check=True,env=env(v))

def write_csv(path, rows):
    with path.open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)

def measure(kind, workloads, trials, warmup):
    rows=[]; rng=random.Random(27286)
    raw=out/f'aligned-{kind}-runs.jsonl'
    raw.write_text('')
    for trial in range(trials):
        for fields,args in workloads:
            order=variants.copy();rng.shuffle(order)
            for v in order:
                start=time.monotonic()
                p=subprocess.run([out/(f'{v}-anal-'+{'realworld':'layout','lookup':'bb-lookup','storage':'bb-storage'}[kind]),*map(str,args)],
                                 env=env(v),capture_output=True,text=True,check=True,timeout=300)
                row=json.loads(p.stdout)
                row.update(variant=v,**fields,trial=trial,warmup=warmup and trial==0,wall_s=time.monotonic()-start)
                rows.append(row)
                with raw.open('a') as f:f.write(json.dumps(row)+'\n')
                print(kind,trial,v,fields,'cpu_s='+str(row.get('cpu_s','')),flush=True)
    write_csv(out/f'aligned-{kind}-runs.csv',rows)
    summaries=[]
    for fields,args in workloads:
        selected_case=[r for r in rows if all(r[k]==value for k,value in fields.items())]
        if kind=='realworld':
            identity={(r['functions'],r['blocks'],r['memberships'],r['checksum']) for r in selected_case}
            if len(identity)!=1:raise RuntimeError(('analysis changed',fields,identity))
        for v in variants:
            selected=[r for r in selected_case if r['variant']==v and not r['warmup']]
            result=dict(fields,variant=v,runs=len(selected))
            for key,val in selected[0].items():
                if key in result or key in ['trial','warmup'] or not isinstance(val,(float,int)) or isinstance(val,bool):continue
                values=[r[key] for r in selected]
                result[key]=statistics.median(values);result[key+'_min']=min(values);result[key+'_max']=max(values)
            summaries.append(result)
    write_csv(out/f'aligned-{kind}-results.csv',summaries)

cases={'ls':'elf/ls','pigz':'elf/pigz','libc':'elf/libc-2.27.so','Mastodon':'mach0/Mastodon'}
measure('realworld',[(dict(case=name,command=command),[fixtures/cases[name],command])
                     for name,command in [(n,'aaa') for n in cases]+[('ls','aaaa'),('pigz','aaaa')]],4,True)
measure('lookup',[(dict(length=n,order=o,interleaved=inter),[n,o]+(['lookup'] if inter else []))
                  for n,o,inter in itertools.product([1,8,64,1024,8192],['asc','desc','shuffle'],[False,True])],3,False)
measure('storage',[(dict(mode=m,length=n,initial=c),[m,n,c])
                   for m,n,c in itertools.product(['ptr','pool','inline'],[1,2,8,9,33,64,65,256],[1,2,4,8])],3,False)
print('ALL BENCHMARKS COMPLETE',flush=True)
