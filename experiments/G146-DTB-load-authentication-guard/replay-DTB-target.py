"""Execute original PIL segment code with exact saved DTB payload bytes.

The G136 range/segment runner is hash-pinned and extracted unchanged. File and
zero-fill boundaries now perform real writes into poisoned, isolated model RAM.
Secure responses, allocation, physical metadata translation and logging remain
models. No authentication, phone access or native ownership claim occurs.
"""
from pathlib import Path
import argparse,ast,hashlib,json,re,struct
import pefile
from unicorn import Uc as BaseUc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runner',type=Path,default=w.parent/'charging-G136/emulate-exact-span.py')
p.add_argument('--pil',type=Path,default=w.parent/'charging-G107/private/installed-loaders/PILDxe.efi')
p.add_argument('--payload-dir',type=Path,default=w.parent/'charging-G118/private/firmware-input/firmware/image')
p.add_argument('--adsp-mdt',type=Path,default=w.parent/'charging-G107/private/native-adsp.mdt')
p.add_argument('--native-preflight',type=Path,default=w.parent/'charging-G144/private/native-preflight.txt')
p.add_argument('--native-opas',type=Path,default=w.parent/'charging-G144/private/native-OPAS.bin')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(a.runner.read_bytes())=='a8f562e57607643bfc75b3495ddd40527a5c15f0db90acbb260cb39ec434359c'
raw=a.pil.read_bytes();assert sha(raw)=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
image=pefile.PE(data=raw).get_memory_mapped_image()
payload={n:(a.payload_dir/n).read_bytes()for n in ['adsp_dtb.b00','adsp_dtb.b01','adsp_dtb.b02','adsp_dtb.mdt']}
expected={'adsp_dtb.b00':'6bf39fd29034606433776d7320ad7a12d7372319d8ec364bbeb671e82d99155c',
 'adsp_dtb.b01':'f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94',
 'adsp_dtb.b02':'437edfdb94ac2b8775c93309edbf828e906ddf4f24123d8c245e94d5767977fb',
 'adsp_dtb.mdt':'5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1'}
assert {n:sha(b)for n,b in payload.items()}==expected
metadata={'adsp':a.adsp_mdt.read_bytes(),'dtb':payload['adsp_dtb.mdt']}
assert sha(metadata['adsp'])=='353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8'
text=a.native_preflight.read_text()
assert sha(a.native_preflight.read_bytes())=='7544da21159c611191219f3246b281efc047022c8980577c7a418be8c00a319d'
file_rows=re.findall(r'^file (\d+) ([a-z0-9_.]+) bytes=(\d+) read=(\d+) status=Success$',text,re.M)
assert len(file_rows)==64 and all(int(v[0])==i and v[2]==v[3]for i,v in enumerate(file_rows))
files={r[1]:int(r[2])for r in file_rows}
for name,data in payload.items():assert files[name]==len(data)
opas=a.native_opas.read_bytes()
assert sha(opas)=='273ca67294c1335e1417c7437df6abc3ae8561f1e4457d0c545fd0683e94db18'
assert len(opas)==36+1608 and opas[:4]==b'OPAS' and sum(opas)%256==0
assert struct.unpack_from('<Q',opas,44)[0]==0x314154454d383231
native_config=opas[36+344:36+344+568]
assert sha(native_config)=='b0dbed167e1ad77a411c409beb7cdec9204822356a8245982884f63d6f924ea1'
assert hashlib.sha256(native_config).digest()==opas[36+280:36+280+32]
assert struct.unpack_from('<QI',native_config)==(3,2)
ARENA,END,TARGET,RESERVED=0x30000000,0x10000000,0x9e980000,0x80000
SAVED=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
fixture={};machines=[];events=[]

def Uc(*args,**kwargs):
    u=BaseUc(*args,**kwargs);machines.append(u)
    u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
    u.mem_map(TARGET,RESERVED);u.mem_write(TARGET,bytes([0xa5])*RESERVED)
    original_hook_add=u.hook_add
    def block(cpu,pc,n,unused):
        if 0<=pc<len(image):
            assert bytes(u.mem_read(pc,n))==image[pc:pc+n],('original instruction changed',hex(pc))
            fixture['original_blocks']+=1
    def write(cpu,kind,at,n,value,unused):
        assert ARENA<=at and at+n<=ARENA+0x100000 or \
               0x16000<=at and at+n<=len(image) or \
               TARGET<=at and at+n<=TARGET+RESERVED,('unexpected instruction write',hex(at),n)
        if TARGET<=at<TARGET+RESERVED:events.append({'kind':'instruction-write','address':at,'bytes':n})
    original_hook_add(UC_HOOK_BLOCK,block);original_hook_add(UC_HOOK_MEM_WRITE,write)
    def hook_add(kind,callback,*args,**kwargs):
        if kind!=UC_HOOK_CODE:return original_hook_add(kind,callback,*args,**kwargs)
        def hook(cpu,pc,n,unused):
            if pc==0x265c and not fixture['config_installed']:
                # Replace the G136 hand-built config with the complete native
                # G144 record. Only the same observed override-byte changes.
                cfg=ARENA+0x2000
                assert struct.unpack('<IQQ',u.mem_read(cfg+0xec,20))==(36,TARGET,RESERVED)
                replacement=bytearray(native_config);replacement[0x102]=fixture['override']
                u.mem_write(cfg,bytes(replacement));fixture['config_installed']=True
            if pc==0x6cd8:
                at=u.reg_read(UC_ARM64_REG_X0);b=bytes(u.mem_read(at,128))
                end=next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0')
                name=b[:end].decode('utf-16le').rsplit('\\',1)[-1]
                countp=u.reg_read(UC_ARM64_REG_X6)
                count=struct.unpack('<Q',u.mem_read(countp,8))[0]
                dest,capacity=struct.unpack('<QQ',u.mem_read(u.reg_read(UC_ARM64_REG_SP),16))
                assert name in payload and count==capacity==len(payload[name])
                assert name=='adsp_dtb.b01' and dest==TARGET
                callback(cpu,pc,n,unused)
                returned=struct.unpack('<Q',u.mem_read(countp,8))[0]
                assert 0<returned<=count
                u.mem_write(dest,payload[name][:returned])
                events.append({'kind':'file-copy-model','name':name,'address':dest,'bytes':returned,
                               'sha256':sha(payload[name][:returned])})
                return
            if pc==0x7e34:
                dest,count=[u.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1]]
                assert TARGET<=dest<=dest+count<=TARGET+RESERVED
                callback(cpu,pc,n,unused)
                if count:u.mem_write(dest,bytes(count));events.append({'kind':'zero-model','address':dest,'bytes':count})
                return
            callback(cpu,pc,n,unused)
        return original_hook_add(kind,hook,*args,**kwargs)
    u.hook_add=hook_add
    return u

nodes=[n for n in ast.parse(a.runner.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='run']
assert len(nodes)==1
env=dict(globals());exec(compile(ast.Module(body=nodes,type_ignores=[]),str(a.runner),'exec'),env)
rows=[]
plans=[('native-G144-address',dict(override=1,segments=True)),
       ('original-config-address',dict(override=0,segments=True)),
       ('INIT-error-before-copy',dict(override=1,scm_fail=0x2000201,segments=True)),
       ('MEM_SETUP-error-before-copy',dict(override=1,scm_fail=0x2000202,segments=True)),
       ('MEM_SETUP-diagnostic-stop',dict(override=1,scm_fail=0x2000202,scm_fail_status=0x8000000000000015,segments=True)),
       ('short-file-read',dict(override=1,segments=True,short_file=True)),
       ('bad-metadata-magic',dict(override=1,segments=True,bad_magic=True))]
for name,kw in plans:
    events.clear();machines.clear();fixture.update(original_blocks=0,config_installed=False,override=kw['override'])
    result=env['run']('dtb',base=TARGET,size=RESERVED,**kw)
    assert len(machines)==1
    ram=bytes(machines[0].mem_read(TARGET,RESERVED));expected_ram=bytearray([0xa5])*RESERVED
    for e in events:
        assert e['kind']!='instruction-write','Unexpected original direct destination write outside file/zero service boundaries'
        start=e['address']-TARGET
        expected_ram[start:start+e['bytes']]=payload[e['name']][:e['bytes']]if e['kind']=='file-copy-model'else bytes(e['bytes'])
    assert ram==bytes(expected_ram)
    if name in ['native-G144-address','original-config-address']:
        assert result['validation_status']==result['range_status']==result['segment_status']==0
        assert len(events)==1 and events[0]['kind']=='file-copy-model'and events[0]['bytes']==8376
        assert sha(ram[:8376])==expected['adsp_dtb.b01']and ram[8376:]==bytes([0xa5])*(RESERVED-8376)
    if 'before-copy'in name or name=='MEM_SETUP-diagnostic-stop' or name=='bad-metadata-magic':assert not events
    if name=='INIT-error-before-copy':
        assert result['validation_status']==7 and result['range_status']is None and len(result['SCM_events'])==1
    if name in ['MEM_SETUP-error-before-copy','MEM_SETUP-diagnostic-stop']:
        assert result['range_status']==7 and result['segment_status']is None and len(result['SCM_events'])==2
    if name=='short-file-read':
        assert result['segment_status']==11 and len(events)==1 and events[0]['bytes']==8375
    if name=='bad-metadata-magic':assert result['validation_status']==1 and not result['SCM_events']
    rows.append({'case':name,'original_result':result,'target_events':list(events),
                 'original_blocks':fixture['original_blocks'],'target_payload_sha256':sha(ram[:8376]),
                 'outside_actual_write_extents_unchanged':True})
report={'passed':True,'cases':len(rows),'native_operations':0,'authentication_calls':0,
        'original_runner_sha256':sha(a.runner.read_bytes()),'model_source_sha256':sha(Path(__file__).read_bytes()),
        'PIL_sha256':sha(raw),'payload_inputs_sha256':expected,'native_preflight_sha256':sha(a.native_preflight.read_bytes()),
        'native_OPAS_sha256':sha(opas),'native_DTB_config_sha256':sha(native_config),
        'config_fixture':'Complete native G144 config; only override102h varies as explicitly labeled.',
        'target_base':TARGET,'reserved_bytes':RESERVED,'actual_payload_bytes':8376,'CPU_pages_covering_payload':3,
        'results':rows,'limits':['File and zero boundaries write exact saved data into poisoned isolated model RAM; these are explicit service models.',
        'SCM responses/allocation/physical metadata translation/logging remain modeled; original range/segment code executes unchanged.',
        'No authentication, PRE/POST proxy, native target access, DMA/stage2 ownership or startup is qualified.']}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
