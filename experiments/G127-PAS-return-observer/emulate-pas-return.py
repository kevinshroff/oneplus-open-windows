"""Run original PIL/SCM return paths; only secure execution and UEFI services modelled.

No ELF load or native operation. The real candidate INI parser supplies the
record fields. SCM's ARMv8 path executes through its original SMC loop, with the
SMC instructions replaced by explicit fixture outputs and legacy response-buffer
writes. Both original transition loops execute. Native results/ABI are unknown.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_BLOCK
from unicorn.arm64_const import *

p=argparse.ArgumentParser(description=__doc__)
for n in ['pil','scm','config','bindings','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
PIL,SCM,ARENA,STOP=0x50000000,0x51000000,0x30000000,0x10000000
MASK=(1<<64)-1
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
raws={'PIL':a.pil.read_bytes(),'SCM':a.scm.read_bytes()}
assert sha(raws['PIL'])=='75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
assert sha(raws['SCM'])=='847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab'
binding=json.loads(a.bindings.read_text())
images={};originals={};sizes={}
for label,base in [('PIL',PIL),('SCM',SCM)]:
    pe=pefile.PE(data=raws[label]);originals[label]=pe.get_memory_mapped_image()
    assert binding[label]['sha256']==sha(raws[label])
    for r in binding[label]['routines']:
        assert r['complete'] and sha(pe.get_data(int(r['RVA'],16),r['bytes']))==r['bytes_sha256']
    pe.relocate_image(base);images[label]=pe.get_memory_mapped_image();sizes[label]=pe.OPTIONAL_HEADER.SizeOfImage
config=a.config.read_bytes()
assert sha(config)=='7308b7ba08813cd6f693742ba1ce8a48cd5e80bcc000d045eb774837e47c0645'

class ModelStop(Exception):pass

def machine(*,abi='armv8',tz=(0,),payload=0,event_fail=0,locate_error=False,alloc_fail=False):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for label,base in [('PIL',PIL),('SCM',SCM)]:
        u.mem_map(base,(sizes[label]+4095)&~4095);u.mem_write(base,images[label])
    u.mem_map(ARENA,0x1000000);u.mem_map(STOP,4096)
    u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
    bs=ARENA+0x10000;ctx=ARENA+0x1000;cfg=ARENA+0x2000;state=ARENA+0x3000;imem=ARENA+0x30000
    q=lambda at,v:u.mem_write(at,struct.pack('<Q',v&MASK))
    d=lambda at,v:u.mem_write(at,struct.pack('<I',v&0xffffffff))
    readq=lambda at:struct.unpack('<Q',u.mem_read(at,8))[0]
    readd=lambda at:struct.unpack('<I',u.mem_read(at,4))[0]
    q(PIL+0x1b168,bs);q(SCM+0xe5a8,bs)
    for off,stub in [(0x148,0),(0x140,4),(0x18,8),(0x20,12)]:q(bs+off,ARENA+0xf00000+stub)
    u.mem_write(ARENA+0x20000,config+b'\0')
    x={'phase':'init','heap':ARENA+0x40000,'events':[],'SCM_calls':[],'active_SCM':None,'secure_entries':0,'ticks':0,'blocks':{'PIL':0,'SCM':0}}
    def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&MASK);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_X30))
    def wide(at):
        b=bytes(u.mem_read(at,256));end=next(i for i in range(0,len(b),2)if b[i:i+2]==b'\0\0');return b[:end].decode('utf-16le')
    def alloc(n):
        assert 0<n<=0x10000;v=x['heap'];x['heap']=(v+n+31)&~31;assert x['heap']<ARENA+0xc00000;return v
    def code(cpu,pc,n,unused):
        z=[u.reg_read(r)for r in regs]
        active=x['active_SCM']
        if active and pc==active['return_PC']:
            active['status']=hex(z[0]);active['results']=[hex(readq(active['results_pointer']+8*i))for i in range(4)]
            x['SCM_calls'].append({k:v for k,v in active.items()if k not in ['return_PC','results_pointer']});x['active_SCM']=None
        if pc==PIL+0x4cc8:ret(0);return
        if pc==PIL+0x71ec:
            assert wide(z[0])=='uefipil.cfg';q(z[1],ARENA+0x20000);q(z[2],len(config));ret();return
        if pc==PIL+0x79ec:ret(alloc(z[0]));return
        if pc in [PIL+0x7b14,PIL+0x7b80,SCM+0x6ffc,SCM+0x306c]:ret();return
        if pc in [PIL+0x7c7c,PIL+0x4bfc,PIL+0x10d8]:raise AssertionError(('OEM assertion',hex(pc)))
        if pc==ARENA+0xf00000:
            assert z[1:4]==[PIL+0x160c8,PIL+0x16188,0];ret();return
        if pc==ARENA+0xf00004:
            assert bytes(u.mem_read(z[0],16))==bytes(u.mem_read(PIL+0x160d8,16))
            q(z[2],SCM+(0xe140 if abi=='armv8'else 0xe0e8));ret(0x800000000000000e if locate_error else 0);return
        if pc==ARENA+0xf00008:
            assert z[0]==8;x['events'].append({'raise_TPL':8});ret(4);return
        if pc==ARENA+0xf0000c:
            assert z[0]==4;x['events'].append({'restore_TPL':4});ret();return
        if pc==PIL+0x1c2c and x['phase']=='init':raise AssertionError('AUTO unexpectedly requests DSP')
        if pc==PIL+0x761c:
            x['events'].append({'cache_clean_modeled':[hex(z[0]),hex(z[1])]});ret();return
        if pc==PIL+0x49a0:
            assert z[0]==ctx and z[1]in [1,2,4];x['events'].append({'PIL_proxy_event_model':z[1]})
            ret(5 if z[1]==event_fail else 0);return
        if pc in [PIL+0x62b4,PIL+0x11cd4,SCM+0x6ca8]:x['ticks']+=1;ret(x['ticks']);return
        if pc in [SCM+0x3f94,SCM+0x185c]:
            assert x['active_SCM']is None
            x['active_SCM']={'command':hex(z[1]),'param_id':hex(z[2]),'arguments':[hex(readq(z[3]+8*i))for i in range(10)],'results_pointer':z[4],'return_PC':u.reg_read(UC_ARM64_REG_X30)}
        if pc==SCM+0x8d1c:
            assert abi=='legacy'and z[0]==80;ret(0 if alloc_fail else alloc(80));return
        if pc==SCM+0x8d98:
            assert abi=='legacy';i=x['secure_entries'];x['secure_entries']+=1;b=readq(SCM+0xe230);assert b
            if i>=len(tz):raise ModelStop('Original legacy SMC loop requested another response; no native latency bound is established')
            if not i:assert z[0]==1 and z[2]==b
            assert readd(b+4)==16 and readd(b+8)==56
            offset=readd(b+8);dataoff=readd(b+offset+4);assert dataoff==12
            if tz[i]==0:
                for j,v in enumerate([1,payload,0,0]):d(b+offset+dataoff-4+4*j,v)
            u.reg_write(UC_ARM64_REG_X0,tz[i]&MASK);u.reg_write(UC_ARM64_REG_PC,pc+4);return
        if pc==SCM+0x8e94:
            assert abi=='armv8'
            i=x['secure_entries'];x['secure_entries']+=1
            if i>=len(tz):raise ModelStop('Original SMC loop requested another response; no native latency bound is established')
            if not i:assert z[0]==int(x['active_SCM']['command'],16)and z[1]==int(x['active_SCM']['param_id'],16)
            for reg,v in zip(regs[:7],[tz[i],payload,0,0,0,0,0]):u.reg_write(reg,v&MASK)
            u.reg_write(UC_ARM64_REG_PC,pc+4);return
        if not(PIL+0x1000<=pc<PIL+0x12000 or SCM+0x1000<=pc<SCM+0xd000):raise AssertionError(('unmodelled address',hex(pc)))
    def block(cpu,pc,n,unused):
        for label,base in [('PIL',PIL),('SCM',SCM)]:
            if base<=pc<base+len(originals[label]):
                off=pc-base;assert bytes(u.mem_read(pc,n))==originals[label][off:off+n],('modified original code',label,hex(off));x['blocks'][label]+=1
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_BLOCK,block)
    def call(entry,args=()):
        for reg,v in zip(regs,list(args)+[0]*(8-len(args))):u.reg_write(reg,v&MASK)
        u.reg_write(UC_ARM64_REG_SP,ARENA+0xff0000);u.reg_write(UC_ARM64_REG_X30,STOP)
        canaries=[0x8888000000000000+i*256 for i in range(len(saved))]
        for r,v in zip(saved,canaries):u.reg_write(r,v)
        u.emu_start(entry,STOP,count=2000000)
        assert u.reg_read(UC_ARM64_REG_PC)==STOP,'No completion after instruction bound'
        assert [u.reg_read(r)for r in saved]==canaries,'callee-saved ABI'
        return u.reg_read(UC_ARM64_REG_X0)
    return u,x,call,q,d,readq,readd,ctx,cfg,state,imem,wide

# Execute the actual candidate parser once. Later fixtures reuse exactly its
# record bytes, while context/SCM/proxy and IMEM storage remain explicit models.
u,x,call,q,d,rq,rd,ctx,cfg,state,imem,wide=machine()
assert call(PIL+0x1588)==0 and rq(PIL+0x166d8)==0
parsed={};profiles={}
for name in ['FULL_ADSP','FULL_ADSP_DTB']:
    u.mem_write(ARENA+0x9000,name.encode('utf-16le')+b'\0\0');ptr=call(PIL+0x3f58,[ARENA+0x9000]);assert ptr
    parsed[name]=bytes(u.mem_read(ptr,0x238));profiles[name]={'media':rq(ptr),'format':rd(ptr+8),'image_id':rd(ptr+0xec),'base':hex(rq(ptr+0xf0)),'bytes':rq(ptr+0xf8),'flags_100_102':list(u.mem_read(ptr+0x100,3)),'label':wide(ptr+0x4c),'preimage':wide(ptr+0x174)}
assert profiles['FULL_ADSP']=={'media':3,'format':2,'image_id':1,'base':'0x9ea00000','bytes':0x4880000,'flags_100_102':[1,0,1],'label':'adsp_ro','preimage':'FULL_ADSP_DTB'},profiles
assert profiles['FULL_ADSP_DTB']['image_id']==36 and profiles['FULL_ADSP_DTB']['flags_100_102']==[0,0,0]

def run(name,*,entry='auth',abi='armv8',tz=(0,),payload=0,event_fail=0,locate_error=False,alloc_fail=False,command=0x2000205,image='FULL_ADSP',info=None,unlock=None):
    u,x,call,q,d,rq,rd,ctx,cfg,state,imem,wide=machine(abi=abi,tz=tz,payload=payload,event_fail=event_fail,locate_error=locate_error,alloc_fail=alloc_fail)
    x['phase']='test';u.mem_write(cfg,parsed[image]);q(ctx,cfg);q(ctx+8,state);q(state,profiles[image]['base']and int(profiles[image]['base'],16));q(state+8,profiles[image]['bytes'])
    q(PIL+0x165c8,imem);d(PIL+0x165d0,0x100);d(PIL+0x163c0,0)
    if info is not None:u.mem_write(cfg+0x100,bytes([info]))
    if unlock is not None:u.mem_write(cfg+0x101,bytes([unlock]))
    stopped=None;status=None
    try:
        if entry=='auth':status=call(PIL+0x373c,[ctx])
        elif entry=='post':status=call(PIL+0x3854,[ctx])
        else:
            assert entry=='wrapper';paramid,more={0x2000201:(0x82,[0x38000000]),0x2000202:(3,[int(profiles[image]['base'],16),profiles[image]['bytes']]),0x2000205:(1,[])}[command]
            status=call(PIL+0x248c,[ctx,command,paramid,profiles[image]['image_id'],*more])
    except ModelStop as e:stopped=str(e)
    events=[e['PIL_proxy_event_model']for e in x['events']if 'PIL_proxy_event_model'in e]
    record=bytes(u.mem_read(imem,20)).hex()if rd(PIL+0x163c0)else None
    return {'case':name,'entry':entry,'ABI_fixture':abi,'image':image,'backend_transport_fixture':list(tz),'backend_service_result_fixture':hex(payload&MASK),'PIL_return':None if status is None else hex(status),'model_stopped_without_completion_claim':stopped,'proxy_events_modeled':events,'SCM_calls':x['SCM_calls'],'secure_entries_modeled':x['secure_entries'],'IMEM_entry_model':record,'original_blocks_executed':x['blocks']}

rows=[]
for abi in ['armv8','legacy']:
    for image in ['FULL_ADSP','FULL_ADSP_DTB']:
        for payload in [0,-7]:
            r=run(abi+'-auth-'+image+'-'+str(payload),abi=abi,image=image,payload=payload);rows.append(r)
            assert r['PIL_return']=='0x0'and r['proxy_events_modeled']==[1,2]and len(r['SCM_calls'])==1
            assert r['SCM_calls'][0]['status']=='0x0'and int(r['SCM_calls'][0]['results'][1],16)==payload&((1<<(64 if abi=='armv8'else 32))-1)
    for event in [1,2]:
        r=run(abi+'-event-'+str(event),abi=abi,event_fail=event);rows.append(r);assert r['PIL_return']=='0x5'and len(r['SCM_calls'])==int(event==2)
    for transport,payload in ([(-1,0),(-2,-13),(-2,0)]if abi=='armv8'else [(-4,0),(-13,0),(-1,0)]):
        r=run(abi+'-transport-'+str(transport)+'-'+str(payload),abi=abi,tz=(transport,),payload=payload);rows.append(r);assert r['PIL_return']=='0x7'and r['proxy_events_modeled']==[1]
    r=run(abi+'-protocol-missing',abi=abi,locate_error=True);rows.append(r);assert r['PIL_return']=='0x7'and not r['SCM_calls']
    for command in [0x2000201,0x2000202]:
        r=run(abi+'-wrapper-'+hex(command),entry='wrapper',abi=abi,command=command,payload=-7);rows.append(r);assert r['PIL_return']=='0x0'
    for event in [0,4]:
        r=run(abi+'-post-event-'+str(event),entry='post',abi=abi,event_fail=event);rows.append(r);assert r['PIL_return']=='0x0'and r['proxy_events_modeled']==[4]and not r['SCM_calls']and r['IMEM_entry_model']
    r=run(abi+'-post-shutdown',entry='post',abi=abi,unlock=1);rows.append(r);assert r['PIL_return']=='0x0'and r['SCM_calls'][0]['command']=='0x42000206'
r=run('armv8-interrupted-once',tz=(1,0));rows.append(r);assert r['PIL_return']=='0x0'and r['secure_entries_modeled']==2
r=run('armv8-still-interrupted',tz=(1,1,1));rows.append(r);assert r['PIL_return']is None and r['model_stopped_without_completion_claim']
r=run('legacy-interrupted-once',abi='legacy',tz=(1,0));rows.append(r);assert r['PIL_return']=='0x0'and r['secure_entries_modeled']==2
r=run('legacy-still-interrupted',abi='legacy',tz=(1,1,1));rows.append(r);assert r['PIL_return']is None and r['model_stopped_without_completion_claim']
r=run('legacy-allocation-failure',abi='legacy',alloc_fail=True);rows.append(r);assert r['PIL_return']=='0x7'and not r['secure_entries_modeled']

result={'passed':True,'cases':len(rows),'PIL_sha256':sha(raws['PIL']),'SCM_sha256':sha(raws['SCM']),'candidate_config_sha256':sha(config),'actual_candidate_parser_executed':True,'candidate_profiles':profiles,'results':rows,'native_operations':0,'limits':['No native ABI choice, secure firmware result, authentication, DSP start or charging is established.','SMC register outputs/legacy response-buffer writes, UEFI services, time, cache clean, proxy callbacks and IMEM backing are models. Both original SMC transition loops execute.','Original metadata/ELF loading is not repeated; this qualifies new authentication/return and callback boundaries.','Both original positive-return loops lack a native bound; nonterminal cases stop the model without claiming completion.']}
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k not in ['results','limits']},indent=2))
