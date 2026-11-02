"""Resolve stock root0 supplies, pinctrl and variable-width clock specifiers."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fdt',type=Path,required=True)
p.add_argument('--parser',type=Path,default=Path(__file__).with_name('fdtree.py'))
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
assert not a.output.exists()
assert hashlib.sha256(a.fdt.read_bytes()).hexdigest()=='e894b0002340de8ff9bfd6610b14d900381a714c43b7ad7d9e31d72e599c4da0'
spec=importlib.util.spec_from_file_location('fdt',a.parser)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=m.Fdt.read(a.fdt);ph=f.phandles()
strings={'compatible','regulator-name','clock-names','pinctrl-names','status','reg-name','function','qcom,resource-name'}
def describe(n):
    props={}
    for k,b in f.nodes[n].items():
        if k=='phandle':continue
        if not b:value=True
        elif k in strings or k.endswith('-names'):value=f.strings(n,k)
        elif len(b)%4==0:value=[hex(v)for v in f.cells(n,k)]
        else:value={'raw_hex':b.hex()}
        props[k]=value
    return {'node':n,'properties':props}
root='/soc/qcom,pcie@1c00000'
names=f.strings(root,'clock-names');data=f.cells(root,'clocks');at=0;clocks=[]
for name in names:
    node=ph[data[at]];at+=1
    count=f.cells(node,'#clock-cells')[0];args=data[at:at+count];at+=count
    clocks.append({'name':name,'args':args,'provider':describe(node)})
assert at==len(data) and len(clocks)==13
pending=[root,'/soc/qcom,cnss-qca-converged/chip_cfg@0'];seen=set();nodes=[]
while pending:
    n=pending.pop(0)
    if n in seen:continue
    seen.add(n);nodes.append(describe(n))
    for k in f.nodes[n]:
        if k.endswith('-supply'):pending.append(ph[f.cells(n,k)[0]])
        if k.startswith('pinctrl-') and k!='pinctrl-names':pending.extend(ph[v]for v in f.cells(n,k))
result={'input_sha256':hashlib.sha256(a.fdt.read_bytes()).hexdigest(),'source_scope':'Normalized stock tree, not live Android','root':root,'clock_specs':clocks,'nodes':nodes,'native_selection':'G124/G125 GPIO83 low selects this source branch; endpoint unverified','native_configuration_writes':0}
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'clocks':len(clocks),'nodes':len(nodes),'source_only':True}))
