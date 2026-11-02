"""Derive the exact guarded GPIO addresses from pinned source and stock FDT."""
from pathlib import Path
import argparse,hashlib,json,re,sys
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--pinctrl',required=True,type=Path);p.add_argument('--dtb',required=True,type=Path)
p.add_argument('--fdt-helper-dir',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
p.add_argument('--spmi-source',required=True,type=Path);p.add_argument('--inventory',required=True,type=Path)
p.add_argument('--native-log',required=True,type=Path)
a=p.parse_args();assert not a.output.exists()
sys.path.insert(0,str(a.fdt_helper_dir));from fdtree import Fdt
f=Fdt.read(a.dtb);node='/soc/pinctrl@f000000';base,size=f.cells(node,'reg');assert base==0xf000000 and size==0x1000000
s=a.pinctrl.read_text()
def define(n):
 m=re.findall(r'^#define '+n+r'\s+(0x[0-9a-fA-F]+)\s*$',s,re.M);assert len(m)==1;return int(m[0],16)
start,stride=define('REG_BASE'),define('REG_SIZE');assert start==0x100000 and stride==0x1000
assert '.ctl_reg = REG_BASE + REG_SIZE * id' in s and '.io_reg = REG_BASE + 0x4 + REG_SIZE * id' in s
regs={}
for gpio in [10,24]:
 ctl=base+start+stride*gpio;io=ctl+4;assert base<=ctl<io<base+size
 regs['GPIO'+str(gpio)]={'control':hex(ctl),'io':hex(io)}
spmi=a.spmi_source.read_text();assert 'offset = 0x1000 * apid;'in spmi and 'offset = 0x8000 * pmic_arb->ee + 0x20 * apid;'in spmi
bus='/soc/qcom,spmi@c42d000';names=f.strings(bus,'reg-names');cells=f.cells(bus,'reg');regions={name:tuple(cells[i*2:i*2+2])for i,name in enumerate(names)}
inv=json.loads(a.inventory.read_text());route=None
for row in inv['map_rows']:
 if int(row['ppid'],16)==0x1c4 and (route is None or row['owner']==0):route=row
assert route['owner']==0 and route['apid']==695
apid=route['apid'];obs=regions['obsrvr'][0]+apid*0x20;wr=regions['chnls'][0]+apid*0x1000
assert obs+0x20<=sum(regions['obsrvr']) and wr+0x20<=sum(regions['chnls'])
spmi_regs={'observer':hex(obs),'write_channel':hex(wr),'route_map':hex(regions['core'][0]+0x2000+4*apid),'owner':hex(regions['cnfg'][0]+4*apid)}
log=a.native_log.read_text(errors='strict');lines=log.splitlines();lo=lines.index('G20_GPIO0_BEGIN');hi=lines.index('G20_GPIO0_END',lo+1);sample=lines[lo:hi]
for pin,row in regs.items():
 addr=int(row['control'],16);found=[]
 for line in sample:
  m=re.fullmatch(r'#\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s*',line)
  if m and int(m[1],16)==addr:found.append([int(m[i],16)for i in range(2,6)])
 assert len(found)==2 and found[0]==found[1],(pin,found)
 row['historical_native_control']=hex(found[0][0]);row['historical_native_io']=hex(found[0][1])
r={'spmi_source_sha256':hashlib.sha256(a.spmi_source.read_bytes()).hexdigest(),'SPMI_registers':spmi_regs,'native_reference_log':a.native_log.name,'native_reference_log_sha256':hashlib.sha256(a.native_log.read_bytes()).hexdigest(),'native_reference_scope':'G20 two-sample GPIO baseline; fresh G26 preflight remains required','pinctrl_sha256' :hashlib.sha256(a.pinctrl.read_bytes()).hexdigest(),'dtb_sha256':hashlib.sha256(a.dtb.read_bytes()).hexdigest(),'FDT_node':node,'FDT_base':hex(base),'controller_GPIO_REG_BASE':hex(start),'GPIO_stride':hex(stride),'registers':regs,'qualification':'source-derived; prior native captures and a fresh complete preflight must also agree'}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
