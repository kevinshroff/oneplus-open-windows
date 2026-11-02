from pathlib import Path
from importlib.machinery import SourceFileLoader
import json
m=SourceFileLoader('strap_policy',str(Path(__file__).with_name('strap-policy.py'))).load_module()
cases=0
for level,device,root in [(0,'0x1107',0),(1,'0x1103',1)]:
    for control in [0,1,2,3,7<<6,1<<11]:
        r=m.decode([[control,level],[control,level]])
        assert r['source_selected_device_id']==device and r['source_selected_root_complex']==root
        assert not r['physical_PCI_identity_verified'];cases+=1
bad=[None,[],[[0,0]],[[0,0],[0,0],[0,0]],[[0],[0]],[[True,0],[True,0]],[[0,-1],[0,-1]],[[0,1<<32],[0,1<<32]],[[0,0],[0,1]],[[0,0],[1,0]],[[4,0],[4,0]],[[15<<2,0],[15<<2,0]],[[1<<9,0],[1<<9,0]],[[1<<12,0],[1<<12,0]]]
for sample in bad:
    try:m.decode(sample)
    except ValueError:cases+=1
    else:raise AssertionError(sample)
print(json.dumps({'passed':True,'cases':cases,'native_operations':0,'physical_identity_claimed':False}))
