"""Derive fixed read-only register/firmware binding and extract two pinned libraries."""
import argparse,hashlib,json,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
G=a.inputs;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
dsdt=G.parent/'source-snapshot/Platforms/KailuaPkg/Device/oneplus-open/ACPI/DSDT.aml';assert sha(dsdt)=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01' and dsdt.stat().st_size==576
shadow=json.loads((G/'rpmh-G29/shadow-plan.json').read_text())['fields'];hdr=json.loads((G/'avdd-G33/trial/native-headers-baseline.json').read_text());assert hdr['success']and hdr['MMIO_writes']==0
fields=[{'name':k,'address':int(v,16)}for k,v in shadow.items()]
seen={x['address']for x in fields}
for row in hdr['reads']:
 addr=int(row['address'],16)
 if addr not in seen:fields.append({'name':'TCS_HEADER_'+hex(addr)[2:],'address':addr});seen.add(addr)
for pin in [10,24,25]:
 for i,key in enumerate(['CONTROL','IO','IRQ_CONFIG','IRQ_STATUS']):fields.append({'name':'GPIO%d_%s'%(pin,key),'address':0xf000000+0x100000+pin*0x1000+i*4})
ranges=[{'base':0x17a20000,'bytes':0x2000},{'base':0x17100000,'bytes':0x1000},{'base':0xf10a000,'bytes':0x1000},{'base':0xf118000,'bytes':0x2000}]
assert len({x['address']for x in fields})==len(fields)
for x in fields:
 match=[i for i,r in enumerate(ranges)if r['base']<=x['address'] and x['address']+4<=r['base']+r['bytes']];assert len(match)==1;x['range']=match[0];x['offset']=x['address']-ranges[match[0]]['base'];assert x['offset']%4==0
b=dsdt.read_bytes();header='/* Generated from exact protected G17 table and qualified native register captures. */\n'
header+='#define G34_REGISTER_COUNT %du\n'%len(fields)
header+='static const UCHAR G34ExpectedDsdt[576]={'+','.join('0x%02x'%x for x in b)+'};\n'
header+='typedef struct {ULONGLONG Base;SIZE_T Bytes;} G34_RANGE;\nstatic const G34_RANGE G34Ranges[]={'+','.join('{0x%xULL,0x%x}'%(r['base'],r['bytes'])for r in ranges)+'};\n'
header+='typedef struct {ULONG Range;ULONG Offset;} G34_FIELD;\nstatic const G34_FIELD G34Fields[]={'+','.join('{%d,0x%x}'%(x['range'],x['offset'])for x in fields)+'};\n'
(a.output/'g34_binding.h').write_text(header)
(A:=a.output/'binding.json').write_text(json.dumps({'DSDT_sha256':sha(dsdt),'DSDT_bytes':576,'fields':fields,'ranges':ranges,'read_only':True,'native_qualified_capture_sha256':sha(G/'avdd-G33/after-resume-state.json'),'RSC_shadow_plan_sha256':sha(G/'rpmh-G29/shadow-plan.json'),'RSC_native_headers_sha256':sha(G/'avdd-G33/trial/native-headers-baseline.json'),'native_GPIO_snapshot_sha256':sha(G/'avdd-G33/external-post-state.json')},indent=2)+'\n')
archive=G/'spi-G27/private/wdk-packages/microsoft.windows.wdk.arm64.nupkg';assert sha(archive)=='e705b2a63eab891def8f98087666f93e8f21da8e3b5def81a624b83fef5bdae9'
libs=[]
with zipfile.ZipFile(archive)as z:
 for n in ['aux_klib.lib','bufferoverflowfastfailk.lib','hal.lib','libcntpr.lib']:
  name='c/Lib/10.0.26100.0/km/ARM64/'+n;data=z.read(name);(a.output/n).write_bytes(data);libs.append({'path':n,'archive_member':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
(a.output/'libraries.json').write_text(json.dumps({'archive_sha256':sha(archive),'files':libs},indent=2)+'\n')
print(json.dumps({'registers':len(fields),'read_only_ranges':len(ranges),'G17_DSDT_bytes':len(b),'extra_libraries':len(libs),'target_access':False}))
