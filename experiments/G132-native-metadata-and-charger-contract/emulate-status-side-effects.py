"""Execute original PMIC status paths with captured reads and modeled SPMI writes."""
from pathlib import Path
import argparse, hashlib, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',required=True,type=Path)
p.add_argument('--native',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args()
assert not a.output.exists()
raw=a.image.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='d8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
image=pefile.PE(data=raw).get_memory_mapped_image()
# The original constructor installs these exact register-table pointers.
# Their blocks are outside the captured read-only 0x25xx..0x29xx window;
# these writes are modeled only, never sent to a hardware backend.
selector_address=0x2500+struct.unpack_from('<H',image,0x3a07a)[0]+struct.unpack_from('<H',image,0x3a07a+0x28)[0]
sdp_address=0x2500+struct.unpack_from('<H',image,0x3a066)[0]+struct.unpack_from('<H',image,0x3a066+0x10)[0]
assert (selector_address,sdp_address)==(0x2cbc,0x2b4a)
packet=a.native.read_bytes()
assert len(packet)==1000 and struct.unpack_from('<I',packet,124)[0]==0
assert struct.unpack_from('<I',packet,148)[0]==17
captured={}
for i in range(17):
    target,off,n,flags=struct.unpack_from('<4I',packet,320+40*i)
    assert target<5 and flags==63 and n<=8
    for j in range(n):
        address=((0x01,0x25,0x26,0x28,0x29)[target]<<8)+off+j
        v=packet[184+8*i+j]
        assert address not in captured or captured[address]==v
        captured[address]=v

ARENA,END=0x30000000,0x10000000
rows=[]

def run(kind,argument=1,missing=False,source=2,apsd=0,read_fail=False,write_fail=None,repeat=False,sid_fail=False):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image)
    u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000)
    u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
    comm,info,context,out,config=[ARENA+n for n in [0x1000,0x2000,0x3000,0x4000,0x5000]]
    u.mem_write(comm,struct.pack('<III',7,0,0));u.mem_write(info,struct.pack('<HBBI',0x2500,2,0xa8,0))
    values=dict(captured);events=[]
    def ret(value=0):
        u.reg_write(UC_ARM64_REG_X0,value&0xffffffffffffffff)
        u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    def hook(cpu,pc,size,user):
        z=[u.reg_read(r)for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
        if pc==0x1715c:
            assert z[:2]==[0x1d,7];ret(1)
        elif pc==0x172d0:
            assert z[0]==0x50;u.mem_write(z[1],struct.pack('<Q',context));ret()
        elif pc in [0xdde4,0xde6c,0xe058]:
            assert z[0]==7
            n,ptr,mask=(z[2],z[3],255)if pc==0xe058 else(1,z[2],255)if pc==0xdde4 else(1,z[3],z[2])
            events.append({'read':hex(z[1]),'bytes':n,'mask':mask,'failure':read_fail})
            if not read_fail:u.mem_write(ptr,bytes(values[z[1]+j]&(mask if n==1 else 255)for j in range(n)))
            ret(1 if read_fail else 0)
        elif pc in [0xdeb4,0xdf44]:
            assert z[0]==7 and z[1]==(selector_address if pc==0xdeb4 else sdp_address)
            mask,value=(255,z[2]&255)if pc==0xdeb4 else(z[2],z[3]&255)
            failure=write_fail==('byte'if pc==0xdeb4 else'masked')
            events.append({'modeled_write':hex(z[1]),'mask':mask,'value':value,'failure':failure})
            if not failure:values[z[1]]=(values.get(z[1],0)&~mask)|(value&mask)
            ret(1 if failure else 0)
        elif pc==0x1d6f8:
            # Initialization/config discovery is an explicit boundary; Float
            # recovery stays disabled in the zeroed modeled config at+0x68.
            u.reg_write(UC_ARM64_REG_X1,0);ret(config)
        elif pc==0x1ce58:
            u.mem_write(z[0],struct.pack('<I',7));ret(1 if sid_fail else 0)
        elif pc==0x1d660:
            u.mem_write(z[0],struct.pack('<I',source));ret()
        elif pc==0x1d0a8:
            u.mem_write(z[0],struct.pack('<I',apsd));ret()
        elif pc==0x18a14:
            events.append({'modeled_delay_ms':z[0]});ret()
        elif pc==0x2507c:
            u.mem_write(z[1],struct.pack('<I',5000 if z[0]!=0 else 0));ret()
        elif pc==0x18c7c:
            events.append({'logging_modeled':True});ret()
    u.hook_add(UC_HOOK_CODE,hook)
    def invoke(entry,args):
        u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
        for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):u.reg_write(r,v)
        u.emu_start(entry,END,count=250000)
        assert u.reg_read(UC_ARM64_REG_PC)==END
        return u.reg_read(UC_ARM64_REG_X0)&0xffffffffffffffff
    if not missing:assert invoke(0x28b90,[comm,info,7])==0
    entry={'selector':0x28f1c,'SDP_once':0x298e4,'state':0x28278,'app_status':0x1e844}[kind]
    args=[7,out]if kind=='state'else[]if kind=='app_status'else[7,argument]
    for call in range(2 if repeat else 1):
        start=len(events)
        status=invoke(entry,args)
        current=events[start:]
        writes=[e for e in current if 'modeled_write'in e]
        if kind=='state':
            assert not writes and status==(4 if missing else 1 if read_fail else 0)
            if not missing and not read_fail:assert struct.unpack('<I',u.mem_read(out,4))[0]==7
        elif kind=='selector':
            assert status==(4 if missing else 2 if argument>=4 else 1 if write_fail=='byte'else 0)
            assert len(writes)==(0 if missing or argument>=4 else 1)
            if writes:assert writes[0]['value']==argument and writes[0]['mask']==255
        elif kind=='SDP_once':
            assert status==(4 if missing else 1 if write_fail=='masked'else 0)
            assert len(writes)==(0 if missing else 1)
            if writes:assert writes[0]['mask']==4 and writes[0]['value']==(argument<<2)&255
        else:
            assert not missing
            if sid_fail or source not in [2,3]:assert not writes
            else:
                assert sum(e['mask']==255 for e in writes)==1
                assert sum(e['mask']==4 for e in writes)==(1 if source==2 and apsd==0 and call==0 else 0)
                assert status==(1 if read_fail or(write_fail=='masked'and source==2 and apsd==0 and call==0)else 0)
                if write_fail=='byte':assert status==0,'The app ignores this selector-write failure'
        rows.append({'kind':kind,'entry':hex(entry),'argument':argument,'missing_context':missing,
                     'source_model':source,'APSD_model':apsd,'read_failure':read_fail,'write_failure':write_fail,
                     'call_index':call,'SID_lookup_failure':sid_fail,'status':hex(status),'events':current})

for value in [0,1,2,3,4,255]:run('selector',argument=value)
run('selector',missing=True);run('selector',write_fail='byte')
for value in [0,1]:run('SDP_once',argument=value)
run('SDP_once',missing=True);run('SDP_once',write_fail='masked')
run('state');run('state',read_fail=True);run('state',missing=True)
run('app_status',repeat=True)
run('app_status',apsd=4)
run('app_status',source=3)
run('app_status',source=4)
run('app_status',sid_fail=True)
run('app_status',read_fail=True)
run('app_status',write_fail='byte')
run('app_status',write_fail='masked',repeat=True)
report={'passed':True,'cases':len(rows),'original_ARM64_instructions':True,'native_operations':0,
        'image_sha256':hashlib.sha256(raw).hexdigest(),'native_capture_sha256':hashlib.sha256(packet).hexdigest(),
        'modeled_write_addresses':{'selector':hex(selector_address),'SDP_once':hex(sdp_address)},
        'models':['Original constructor uses explicit property/peripheral count/allocation models',
                  'SPMI reads consume the saved G131 fixed packet; writes are memory-only models',
                  'Application config,SID lookup,input source/APSD,ADC samples,delay and logging are controlled boundaries'],
        'findings':['Original core status getter28278 does not write; failed output must be rejected.',
                    'App status/log function1e844 can invoke two write helpers: once-per-SDP298e4 and per-log28f1c.',
                    'A failed status read does not prevent the app from issuing its selector write.',
                    'The app ignores selector-write status; failed once-per-SDP setup is latched and skipped on the second modeled call.'],
        'limits':['These are controlled original-code executions,not a native charging transaction.',
                  'Register write locations come from this exact installed register data; no newer generic SMB5 map is substituted.',
                  'No board permission,profile,thermal-policy or charging fix is qualified by these results.'],
        'results':rows}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['passed','cases','original_ARM64_instructions','native_operations']}))
