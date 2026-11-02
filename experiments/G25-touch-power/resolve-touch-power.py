"""Resolve touch GPIOs and supply consumers separately in each candidate FDT.

Candidate stock trees do not establish the DTBO/panel selected by Android.
Phandle numbers are never carried from one tree to another.
"""
from pathlib import Path
import argparse,hashlib,json,sys
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fdt-helper-dir',required=True,type=Path)
p.add_argument('--dtb',required=True,type=Path,action='append')
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();assert not a.output.exists()
sys.path.insert(0,str(a.fdt_helper_dir));from fdtree import Fdt

def properties(f,node,keys):
    out={}
    for k in keys:
        if k not in f.nodes[node]:continue
        out[k]=f.strings(node,k)if k in ['compatible','reg-names','qcom,resource-name','regulator-name','model']else f.cells(node,k)
    return out

report={'authority':'derived stock candidate FDTs; active Android DTBO/panel selection unproven','candidates':[]}
for path in a.dtb:
    raw=path.read_bytes();f=Fdt(raw);ph=f.phandles()
    touches=[n for n in f.nodes if n.endswith('/goodix_gt9966@0')or n.endswith('/goodix_gt9916@0')]
    assert len(touches)==2
    cand={'dtb_sha256':hashlib.sha256(raw).hexdigest(),'model':f.strings('/','model'),'touches':[]}
    supplies=set()
    for n in touches:
        t={'path':n,'compatible':f.strings(n,'compatible'),'resources':{}}
        for k in ['reset-gpio','enable2v8_gpio','irq-gpio','vcc_1v8-supply']:
            cells=f.cells(n,k);provider=ph[cells[0]]
            r={'cells':cells,'provider_path':provider,'provider':properties(f,provider,['compatible','reg','regulator-name','regulator-min-microvolt','regulator-max-microvolt','qcom,init-voltage','qcom,init-mode','qcom,set'])}
            if k.endswith('-supply'):
                supplies.add(cells[0]);parent=provider.rsplit('/',1)[0]
                r['supply_parent_path']=parent;r['supply_parent']=properties(f,parent,['compatible','qcom,resource-name','reg','qcom,set'])
            elif 'spmi@'in provider:
                parent=provider.rsplit('/',1)[0];r['PMIC_parent_path']=parent
                r['PMIC_parent']=properties(f,parent,['compatible','reg'])
            t['resources'][k]=r
        cand['touches'].append(t)
    cand['supply_consumers']=[]
    for node,props in f.nodes.items():
        for key in props:
            if key.endswith('-supply'):
                cells=f.cells(node,key)
                if cells and cells[0]in supplies:cand['supply_consumers'].append(dict(path=node,property=key,provider_path=ph[cells[0]]))
    report['candidates'].append(cand)
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('resolved',len(report['candidates']),'candidate power trees')
