"""Replay original main-image range/segment code with exact saved payloads.

No firmware is built, staged or booted. This establishes a future load contract,
not ownership, accepted native main PAS calls, DTB authentication or DSP startup.
"""
from pathlib import Path
import argparse,ast,gc,hashlib,json,re,struct
import pefile
from unicorn import Uc as BaseUc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runner',type=Path,default=w.parent/'charging-G136/emulate-exact-span.py')
p.add_argument('--pil',type=Path,default=w.parent/'charging-G107/private/installed-loaders/PILDxe.efi')
p.add_argument('--capture',type=Path,default=w.parent/'charging-G118/private/firmware-input/capture.json')
p.add_argument('--payload-dir',type=Path,default=w.parent/'charging-G118/private/firmware-input/firmware/image')
p.add_argument('--native-preflight',type=Path,default=w.parent/'charging-G144/private/native-preflight.txt')
p.add_argument('--native-opas',type=Path,default=w.parent/'charging-G144/private/native-OPAS.bin')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(a.runner.read_bytes())=='a8f562e57607643bfc75b3495ddd40527a5c15f0db90acbb260cb39ec434359c'
raw=a.pil.read_bytes();assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
image=pefile.PE(data=raw).get_memory_mapped_image()
assert sha(a.capture.read_bytes())=='ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882'
capture=json.loads(a.capture.read_text());assert len(capture['files'])==64 and capture['native_source_writes']==0
payload={};input_hashes={}
for row in capture['files']:
 if not(row['Name'].startswith('adsp.b')or row['Name']=='adsp.mdt'):continue
 name=row['Name'];data=(a.payload_dir/name).read_bytes()
 assert len(data)==row['Bytes']and sha(data)==row['SHA256'],name
 payload[name]=data;input_hashes[name]=row['SHA256']
metadata={'adsp':payload['adsp.mdt']}
assert sha(metadata['adsp'])=='353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8'
text=a.native_preflight.read_text()
assert sha(a.native_preflight.read_bytes())=='7544da21159c611191219f3246b281efc047022c8980577c7a418be8c00a319d'
file_rows=re.findall(r'^file (\d+) ([a-z0-9_.]+) bytes=(\d+) read=(\d+) status=Success$',text,re.M)
assert len(file_rows)==64 and all(int(v[0])==i and v[2]==v[3]for i,v in enumerate(file_rows))
files={r[1]:int(r[2])for r in file_rows}
for name,data in payload.items():assert files[name]==len(data),name
opas=a.native_opas.read_bytes()
assert sha(opas)=='273ca67294c1335e1417c7437df6abc3ae8561f1e4457d0c545fd0683e94db18'
assert len(opas)==1644 and opas[:4]==b'OPAS'and sum(opas)%256==0
native_config=opas[36+344+568:36+344+1136]
assert sha(native_config)=='65913a28ec7082cacdaa1dca42719cdf1b748eac153d85c88cf3642961cfa992'
assert hashlib.sha256(native_config).digest()==opas[36+312:36+344]
assert struct.unpack_from('<QI',native_config)==(3,2)
ARENA,END,TARGET,RESERVED=0x30000000,0x10000000,0x9ea00000,0x4880000
assert struct.unpack_from('<IQQ',native_config,0xec)==(1,TARGET,RESERVED)and native_config[0x102]==1
SAVED=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
mdt=metadata['adsp'];phoff=struct.unpack_from('<I',mdt,28)[0];phnum=struct.unpack_from('<H',mdt,44)[0]
assert phnum==59 and struct.unpack_from('<H',mdt,42)[0]==32
layout=[];plan=[];planned_files={}
for index in range(phnum):
 kind,offset,va,pa,stored,memory,flags,align=struct.unpack_from('<8I',mdt,phoff+index*32)
 row={'index':index,'type':kind,'file_offset':offset,'virtual_address':va,'physical_address':pa,'file_bytes':stored,'memory_bytes':memory,'flags':flags,'alignment':align}
 layout.append(row)
 if kind!=1:continue
 assert stored<=memory and TARGET<=pa<=pa+memory<=TARGET+RESERVED
 # Original3478h skips both zero-memory and zero-file-size PT_LOAD entries
 # at350Ch..3518h. It zeroes only a copied segment's memsz-filesz tail.
 if not stored or not memory:continue
 if stored:
  name='adsp.b'+str(index).zfill(2);assert len(payload[name])==stored
  event={'kind':'file-copy-model','name':name,'address':pa,'bytes':stored,'sha256':sha(payload[name])}
  plan.append(event);planned_files[name]=event
 if memory>stored:plan.append({'kind':'zero-model','address':pa+stored,'bytes':memory-stored})
assert len(planned_files)==54
fixture={};machines=[];events=[]

def Uc(*args,**kwargs):
 u=BaseUc(*args,**kwargs);machines.append(u);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
 u.mem_map(TARGET,RESERVED)
 chunk=bytes([0xa5])*0x100000
 for start in range(0,RESERVED,len(chunk)):u.mem_write(TARGET+start,chunk[:min(len(chunk),RESERVED-start)])
 original_hook_add=u.hook_add
 def block(cpu,pc,n,unused):
  if 0<=pc<len(image):
   assert bytes(u.mem_read(pc,n))==image[pc:pc+n],('original instruction changed',hex(pc))
   fixture['original_blocks']+=1
 def write(cpu,kind,at,n,value,unused):
  assert ARENA<=at<=at+n<=ARENA+0x100000 or 0x16000<=at<=at+n<=len(image)or TARGET<=at<=at+n<=TARGET+RESERVED,('unexpected instruction write',hex(at),n)
  if TARGET<=at<TARGET+RESERVED:events.append({'kind':'instruction-write','address':at,'bytes':n})
 original_hook_add(UC_HOOK_BLOCK,block);original_hook_add(UC_HOOK_MEM_WRITE,write)
 def hook_add(kind,callback,*args,**kwargs):
  if kind!=UC_HOOK_CODE:return original_hook_add(kind,callback,*args,**kwargs)
  def hook(cpu,pc,n,unused):
   if pc==0x265c and not fixture['config_installed']:
    cfg=ARENA+0x2000;assert struct.unpack('<IQQ',u.mem_read(cfg+0xec,20))==(1,TARGET,RESERVED)
    replacement=bytearray(native_config);replacement[0x102]=fixture['override']
    u.mem_write(cfg,bytes(replacement));fixture['config_installed']=True
   if pc==0x6cd8:
    at=u.reg_read(UC_ARM64_REG_X0);b=bytes(u.mem_read(at,128));end=next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0')
    name=b[:end].decode('utf-16le').rsplit('\\',1)[-1];assert name in planned_files
    sizep=u.reg_read(UC_ARM64_REG_X6);count=struct.unpack('<Q',u.mem_read(sizep,8))[0]
    dest,capacity=struct.unpack('<QQ',u.mem_read(u.reg_read(UC_ARM64_REG_SP),16))
    expected=planned_files[name];assert count==capacity==expected['bytes']and dest==expected['address']
    callback(cpu,pc,n,unused)
    returned=struct.unpack('<Q',u.mem_read(sizep,8))[0];assert returned==count
    if name==fixture['short_name']:returned-=1;u.mem_write(sizep,struct.pack('<Q',returned))
    assert 0<returned<=count;u.mem_write(dest,payload[name][:returned])
    events.append({'kind':'file-copy-model','name':name,'address':dest,'bytes':returned,'sha256':sha(payload[name][:returned])});return
   if pc==0x7e34:
    dest,count=[u.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1]]
    assert TARGET<=dest<=dest+count<=TARGET+RESERVED
    callback(cpu,pc,n,unused)
    if count:u.mem_write(dest,bytes(count));events.append({'kind':'zero-model','address':dest,'bytes':count})
    return
   callback(cpu,pc,n,unused)
  return original_hook_add(kind,hook,*args,**kwargs)
 u.hook_add=hook_add;return u

nodes=[n for n in ast.parse(a.runner.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='run'];assert len(nodes)==1
env=dict(globals());exec(compile(ast.Module(body=nodes,type_ignores=[]),str(a.runner),'exec'),env)
plans=[('native-config-override1',dict(override=1,segments=True),None),('override0-same-original-address',dict(override=0,segments=True),None),('INIT-error-before-copy',dict(override=1,scm_fail=0x2000201,segments=True),None),('MEM_SETUP-error-before-copy',dict(override=1,scm_fail=0x2000202,segments=True),None),('MEM_SETUP-diagnostic-stop',dict(override=1,scm_fail=0x2000202,scm_fail_status=0x8000000000000015,segments=True),None),('short-first-file',dict(override=1,segments=True),'adsp.b01'),('short-last-file',dict(override=1,segments=True),'adsp.b56'),('bad-metadata-magic',dict(override=1,segments=True,bad_magic=True),None)]
rows=[]
for name,kw,short_name in plans:
 machines.clear();events.clear();gc.collect();fixture.update(original_blocks=0,config_installed=False,override=kw['override'],short_name=short_name)
 result=env['run']('adsp',base=TARGET,size=RESERVED,**kw);assert len(machines)==1
 assert all(e['kind']!='instruction-write'for e in events),'Original direct target write outside modeled service boundary'
 if name in ['native-config-override1','override0-same-original-address']:
  assert result['validation_status']==result['range_status']==result['segment_status']==0 and events==plan
 elif short_name:
  assert result['segment_status']==11
  cut=next(i for i,e in enumerate(plan)if e.get('name')==short_name)
  partial=dict(plan[cut],bytes=plan[cut]['bytes']-1,sha256=sha(payload[short_name][:-1]))
  assert events==plan[:cut]+[partial]
 else:
  assert not events
  if name=='INIT-error-before-copy':assert result['validation_status']==7 and result['range_status']is None and len(result['SCM_events'])==1
  elif name=='bad-metadata-magic':assert result['validation_status']==1 and not result['SCM_events']
  else:assert result['range_status']==7 and result['segment_status']is None and len(result['SCM_events'])==2
 digest=hashlib.sha256()
 for start in range(0,RESERVED,0x100000):
  size=min(0x100000,RESERVED-start);expected=bytearray([0xa5])*size;low=TARGET+start;high=low+size
  for e in events:
   begin=max(low,e['address']);end=min(high,e['address']+e['bytes'])
   if begin>=end:continue
   data=payload[e['name']][begin-e['address']:end-e['address']]if e['kind']=='file-copy-model'else bytes(end-begin)
   expected[begin-low:end-low]=data
  actual=bytes(machines[0].mem_read(low,size));assert actual==expected,(name,hex(low));digest.update(actual)
 rows.append({'case':name,'original_result':result,'target_events':list(events),'original_blocks':fixture['original_blocks'],'poisoned_model_reservation_sha256':digest.hexdigest(),'all_actual_extents_and_untouched_holes_verified':True})
 print(json.dumps({'case':name,'status':result['segment_status'],'file_copies':sum(e['kind']=='file-copy-model'for e in events),'zero_fills':sum(e['kind']=='zero-model'for e in events)}),flush=True)
pages=set()
for e in plan:pages.update(range(e['address']//4096,(e['address']+e['bytes']+4095)//4096))
report={'passed':True,'cases':len(rows),'native_operations':0,'authentication_calls':0,'original_runner_sha256':sha(a.runner.read_bytes()),'model_source_sha256':sha(Path(__file__).read_bytes()),'PIL_sha256':sha(raw),'capture_sha256':sha(a.capture.read_bytes()),'payload_inputs_sha256':input_hashes,'native_preflight_sha256':sha(a.native_preflight.read_bytes()),'native_OPAS_sha256':sha(opas),'native_main_config_sha256':sha(native_config),'config_fixture':'Complete native G144 main config, with only override102h varied as labeled.','target_base':TARGET,'reserved_bytes':RESERVED,'target_end_exclusive':TARGET+RESERVED,'ELF_programs':phnum,'ELF_layout':layout,'complete_target_plan':plan,'file_copies':len(planned_files),'file_copy_bytes':sum(e['bytes']for e in plan if e['kind']=='file-copy-model'),'zero_fills':sum(e['kind']=='zero-model'for e in plan),'zero_fill_bytes':sum(e['bytes']for e in plan if e['kind']=='zero-model'),'CPU_pages_touched':len(pages),'last_loader_write_end_exclusive':max(e['address']+e['bytes']for e in plan),'declared_zero_only_segments_not_touched_by_loader':[r for r in layout if r['type']==1 and r['file_bytes']==0 and r['memory_bytes']>0],'results':rows,'limits':['Original range/segment instructions execute unchanged; file and zero boundaries write exact saved data into isolated poisoned model RAM.','Secure responses, allocation, physical metadata translation, logging and prior DTB success are modeled. No native main-image request or target ownership grant is made.','The full-reservation digest includes model poison in untouched holes; it is not an expected native RAM digest.','The original segment helper does not clear zero-only PT_LOAD entries. Whether secure AUTH clears those entries is not established by this load replay.','No PRE/POST, authentication, DSP execution, GLINK readiness, charging, DMA/stage2 ownership or power lease is qualified.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['passed','cases','file_copies','file_copy_bytes','zero_fills','zero_fill_bytes','CPU_pages_touched','reserved_bytes','target_end_exclusive']},indent=2))
