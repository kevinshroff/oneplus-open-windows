"""Replay the exact PAS MEM_SETUP wrapper with modeled inner-function returns.

This is not the dispatcher, live PIL state/policy or a secure-monitor entry.
BTI/PAC/RETAA mechanics and the inner function's result are explicit models.
"""
from pathlib import Path
import argparse,hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',required=True,type=Path)
p.add_argument('--tz',type=Path,default=w.parent/'secure-memory-G138/private/tz_a.img')
p.add_argument('--proof',type=Path,default=w.parent/'charging-G139/private/TZ-core-complete-bytes-REA.json')
p.add_argument('--dispatch',type=Path,default=w.parent/'secure-memory-G138/private/curated-REA.json')
a=p.parse_args();assert not a.output.exists()
raw=a.tz.read_bytes()
digest=hashlib.sha256(raw).hexdigest()
assert digest=='dbd1e8e09fd6aca142755989b3ce97b5a271dec3432a572a01167849be83ae80'
proof=json.loads(a.proof.read_text())
d=proof['normalized_result'];base=int(d['address'],16);data=bytes.fromhex(d['bytes_hex'])
assert proof['subject']['digest']['sha256']==digest and d['complete']
assert len(data)==d['requested_bytes']==d['returned_bytes']==0x4000
h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);offsets=[]
for n in range(h[10]):
    typ,flags,off,va,pa,size,mem,align=struct.unpack_from('<IIQQQQQQ',raw,h[5]+n*h[9])
    if typ==1 and va<=base and base+len(data)<=va+size:offsets.append(off+base-va)
assert len(offsets)==1 and raw[offsets[0]:offsets[0]+len(data)]==data
dispatch=json.loads(a.dispatch.read_text())['dispatch']
assert dispatch['sha256']==digest and dispatch['derived_bindings']['0x02000202']=={
       'handler':'0xd835e0f0','parameter_id':'0x3'}
ENTRY,INNER,ARENA,STOP=0xd835e0f0,0xd835bb10,0x30000000,0x20000000
rows=[]
for value in [0,0x30003e,-0x30003e,0x300046,-0x300046,-0x80000000,0x7fffffff]:
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,len(data));u.mem_write(base,data)
    u.mem_map(ARENA,0x10000);u.mem_map(STOP,4096)
    stack=ARENA+0xffe0;fp_canary=0x123456789abcdef0;seen=[];inner=[]
    def hook(cpu,pc,n,unused):
        if pc==INNER:
            inner.append(value);u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
            u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
        assert ENTRY<=pc<ENTRY+40
        assert bytes(u.mem_read(pc,n))==data[pc-base:pc-base+n]
        seen.append(pc)
        word=struct.unpack('<I',u.mem_read(pc,4))[0]
        if word in [0xd503245f,0xdac103fe]:u.reg_write(UC_ARM64_REG_PC,pc+4)
        elif word==0xd65f0bff:u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    u.hook_add(UC_HOOK_CODE,hook)
    u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_X29,fp_canary)
    u.reg_write(UC_ARM64_REG_LR,STOP)
    u.emu_start(ENTRY,STOP,count=64)
    result=u.reg_read(UC_ARM64_REG_X0)
    assert u.reg_read(UC_ARM64_REG_PC)==STOP and len(seen)==10 and len(inner)==1
    assert result==(-abs(value)&0xffffffff)
    assert u.reg_read(UC_ARM64_REG_SP)==stack and u.reg_read(UC_ARM64_REG_X29)==fp_canary
    rows.append({'internal_PIL_result_fixture':value,'original_wrapper_X0_return':hex(result),
                 'instructions':len(seen),'inner_PIL_calls_modeled':len(inner)})
out={'passed':True,'cases':len(rows),'TZ_sha256':digest,'REA_bytes_evidence_id':proof['evidence_id'],
     'model_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
     'dispatch_evidence_id':dispatch['evidence_id'],'handler_entry':hex(ENTRY),
     'original_wrapper_bytes_unchanged':True,'native_operations':0,'results':rows,
     'limits':['The inner PIL state/metadata/policy function is an explicit return-value fixture, not executed.',
               'BTI/PAC/RETAA authentication mechanics are modeled.',
               'Return is an ordinary wrapper result before secure-monitor SMC return handling; full native X0 is not reconstructed.']}
a.output.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items()if k!='results'},indent=2))
