"""Generate one proposed fixed resource contract from qualified source ranges.
No firmware publication, driver installation or hardware access occurs here.
"""
from pathlib import Path
import json,hashlib,shutil
w=Path(__file__).resolve().parent;root=w.parent;entries=[]
def add(base,size,rw,role,cache='noncached'):
 entries.append({'base':base,'bytes':size,'write_access':rw,'role':role,'cache':cache})
for base,role in [(0x152000,'GCC votes'),(0x11e000,'primary root/branch clocks'),(0x117000,'secondary root/branch clocks'),(0x123000,'shared controller branch clocks'),(0xf100000,'primary SDA pin'),(0xf101000,'primary SCL pin'),(0xf116000,'secondary SDA pin'),(0xf117000,'secondary SCL pin')]:add(base,0x1000,False,role)
add(0x880000,0x1000,True,'primary GENI I2C engine');add(0x8c0000,0x1000,False,'primary QUP wrapper');add(0x98c000,0x1000,True,'secondary I2C hub engine')
for base,rw,role in [(0xc400000,False,'SPMI arbiter identity'),(0xc402000,False,'SPMI APID map'),(0xc42d000,False,'SPMI APID owners'),(0xc443000,True,'fixed SPMI read-command pages A'),(0xc445000,True,'fixed SPMI read-command pages B')]:add(base,0x1000,rw,role)
add(0x81a04000,0x10000,False,'pinned firmware FDT','cached');add(0x81eff000,0x1000,False,'SMEM TOC');add(0x81e9f000,0x60000,True,'AP/DSP SMEM partition');add(0x408000,0x1000,True,'qualified IPCC doorbell page')
assert len(entries)==20
for a in entries:
 assert a['base']%4096==0 and a['bytes']%4096==0
 for b in entries:
  if a is not b:assert not(a['base']<b['base']+b['bytes']and b['base']<a['base']+a['bytes'])
sources=['charging-G160/probe/g160_driver.c','charging-G160/probe/g102_resources.h','charging-G167/probe/g167_driver.c','charging-G180/native/driver.c']
m={'status':'proposed only; no native resource grant','resources':entries,'sources':{n:hashlib.sha256((root/n).read_bytes()).hexdigest()for n in sources},'unused_source_page_excluded':'0x9c0000: not accessed by the fixed hub query path','shared_clock_pin_review_required':True,'producer_or_battery_qualification':False}
(w/'private/resource-contract.json').write_text(json.dumps(m,indent=2)+'\n')
h=['/* Generated fixed resources, not a user-selected mapping interface. */','#ifndef OP182_RESOURCES_H','#define OP182_RESOURCES_H','#include <stdint.h>','#include <stddef.h>','#define OP182_RESOURCE_COUNT 20u','typedef struct {uint64_t Base;uint32_t Bytes,Write,Cache,Share;}OP182_RESOURCE;','static const OP182_RESOURCE OP182Expected[OP182_RESOURCE_COUNT]={']
for r in entries:h.append(' {UINT64_C(0x%x),0x%x,%u,%u,0}, /* %s */'%(r['base'],r['bytes'],r['write_access'],r['cache']=='cached',r['role']))
h+=['};','uint32_t Op182Validate(const OP182_RESOURCE*,const OP182_RESOURCE*,size_t);','#endif'];(w/'source/resources.h').write_text('\n'.join(h)+'\n')
s=['/* Proposed supplementary namespace; does not replace the existing DSDT. */','DefinitionBlock ("", "SSDT", 2, "OPEN  ", "OPRES182", 0x00000001)','{',' Scope (\\_SB)',' {','  Device (OPBM)','  {','   Name (_HID, "OPEN0182")','   Name (_UID, One)','   Name (_CCA, One)','   Name (_DDN, "OnePlus Open platform resources")','   Name (_STA, 0x0F)','   Name (_CRS, ResourceTemplate ()','   {']
for r in entries:s.append('    Memory32Fixed (%s, 0x%08X, 0x%08X) // %s'%('ReadWrite'if r['write_access']else'ReadOnly',r['base'],r['bytes'],r['role']))
s+=['   })','  }',' }','}'];(w/'acpi/OPRES182.asl').write_text('\n'.join(s)+'\n');shutil.copyfile(root/'charging-G180/native/binding.h',w/'source/binding.h')
print({'proposed_ranges':len(entries),'bytes':sum(x['bytes']for x in entries),'hardware_IO':0,'firmware_publications':0})
