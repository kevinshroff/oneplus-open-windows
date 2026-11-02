"""Extract source candidates and exact firmware ACPI tables, without hardware access."""
from pathlib import Path
import sys,hashlib,json,struct
from importlib.machinery import SourceFileLoader
w=Path(__file__).resolve().parent
fdt_mod=SourceFileLoader('g18fdt',str(w.parent/'maintenance-G18/fdt-analysis/fdtree.py')).load_module()
inv_mod=SourceFileLoader('g106inv',str(w.parent/'charging-G106/inventory-fd.py')).load_module()
sha=lambda b:hashlib.sha256(b).hexdigest()
rows=[]
for base in [1,2]:
 for choice in ['first','last']:
  p=w.parent/f'maintenance-G18/fdt-analysis/private/kalama-candidate-{base}-{choice}.dtb'
  f=fdt_mod.Fdt.read(p);nodes=[];ph=f.phandles()
  for path,props in f.nodes.items():
   if 'compatible'in props and 'qcom,cnss-qca-converged'in f.strings(path,'compatible'):
    gpio=f.cells(path,'qcom,wlan-sw-ctrl-gpio');branches=[]
    for child,cp in f.nodes.items():
     if child.rsplit('/',1)[0]!=path or not child.rsplit('/',1)[1].startswith('chip_cfg@'):continue
     branches.append({'path':child,'supported_ids':[hex(v)for v in f.cells(child,'supported-ids')],
                      'root_complex':f.cells(child,'qcom,wlan-rc-num'),
                      'status':f.strings(child,'status')if'status'in cp else['okay-by-default'],
                      'wlan_enable':f.cells(child,'wlan-en-gpio'),
                      'regulator_phandles':{k:ph[f.cells(child,k)[0]]for k in cp if k.endswith('-supply')}})
    nodes.append({'path':path,'selector_gpio':gpio,'gpio_controller':ph[gpio[0]],'branches':branches})
  rows.append({'base':base,'normalization':choice,'sha256':sha(p.read_bytes()),'wireless':nodes})
assert all(r['wireless']==rows[0]['wireless']for r in rows)
assert len(rows[0]['wireless'])==1 and rows[0]['wireless'][0]['selector_gpio'][1]==83

class Acpi(inv_mod.Inventory):
 def __init__(self):super().__init__();self.tables=[]
 def sections(self,data,owner,path,depth):
  super().sections(data,owner,path,depth)
  if owner['guid']!='7e374e25-8e01-4fee-87f2-390c23c606cd':return
  at=0
  while at<len(data):
   n=int.from_bytes(data[at:at+3],'little');hdr=4
   if n==0xffffff:n=struct.unpack_from('<I',data,at+4)[0];hdr=8
   if data[at+3]==0x19:self.tables.append(data[at+hdr:at+n])
   at=min((at+n+3)&~3,len(data))
fd=(w.parent/'gauges-G104/private/G80-normal-FV.fd').read_bytes();assert sha(fd)=='93fb6c036781ec946aa7a5a91eb21e756dec17ce57447a16b757670a7dda34e1'
a=Acpi();a.volume(fd);out=w/'private/acpi';out.mkdir(exist_ok=True);tables=[]
for b in a.tables:
 sig=b[:4].decode('ascii');assert len(b)>=8 and struct.unpack_from('<I',b,4)[0]==len(b)
 if sig!='FACS':assert len(b)>=36
 p=out/(sig+'.bin')
 if p.exists():assert p.read_bytes()==b
 else:p.write_bytes(b)
 row={'signature':sig,'bytes':len(b),'sha256':sha(b),'template_checksum_residue':sum(b)%256 if sig!='FACS'else None}
 if sig=='MCFG':
  assert (len(b)-44)%16==0
  row['entries']=[{'config_base':hex(addr),'segment':seg,'bus_start':start,'bus_end':end}for addr,seg,start,end,res in struct.iter_unpack('<QHBBI',b[44:])]
 if sig=='IORT':
  count,at=struct.unpack_from('<II',b,36);records=[]
  for i in range(count):
   assert at+16<=len(b);typ,n,rev,ident,nmap,moff=struct.unpack_from('<BHBIII',b,at);assert n>=16 and at+n<=len(b)
   rec={'type':typ,'revision':rev,'identifier':hex(ident),'mapping_count':nmap,'bytes':n}
   if typ==1:
    end=b.find(b'\0',at+29,at+n);assert end!=-1;rec['named_component']=b[at+29:end].decode('ascii')
   if typ==2 and n>=33:rec['pci_segment']=struct.unpack_from('<I',b,at+28)[0]
   records.append(rec);at+=n
  row['nodes']=records
 tables.append(row)
assert next(t['sha256']for t in tables if t['signature']=='DSDT')=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
x={'source_candidates':rows,'all_four_wireless_subtrees_equal':True,'firmware_FD_sha256':sha(fd),'included_ACPI_tables':tables,
   'limits':['The normalized Android trees are source candidates, not a captured running Android tree.','Static firmware ACPI tables do not establish the complete live Windows table set or a powered PCIe link.','No MMIO, configuration read, driver install or phone action.']}
(w/'private/topology.json').write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps({'wireless':rows[0]['wireless'],'table_summary':[(t['signature'],t['bytes'])for t in tables],'MCFG':[t for t in tables if t['signature']=='MCFG'],'IORT':[t for t in tables if t['signature']=='IORT']},indent=2))
