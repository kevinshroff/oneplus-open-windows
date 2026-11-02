"""Observe original SCM response storage at its modeled serial callback entry.

Only the existing G136 model's service boundaries are wrapped. Original SCM,
SMC-loop and formatter instructions stay unchanged; no native operation occurs.
"""
from pathlib import Path
import argparse,ast,base64,hashlib,json,struct
import pefile
from unicorn import Uc as BaseUc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--runner',type=Path,default=w.parent/'charging-G136/emulate-scm-log.py')
parser.add_argument('--scm',type=Path,default=w.parent/'charging-G127/private/ScmDxe-G80.efi')
a=parser.parse_args();assert not a.output.exists()
source=a.runner
assert hashlib.sha256(source.read_bytes()).hexdigest()=='b28cf76794a50bc808e3c40739ce24eba3a79e67f23ef766683309d5920ff497'
raw=a.scm.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab'
SCM,ARENA,STOP=0x51000000,0x30000000,0x10000000
pe=pefile.PE(data=raw);pe.relocate_image(SCM);image=pe.get_memory_mapped_image();mask=(1<<64)-1
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
observed=[];fixture={}

def Uc(*args,**kwargs):
    uc=BaseUc(*args,**kwargs)
    original_hook_add=uc.hook_add
    def hook_add(kind,callback,*args,**kwargs):
        if kind!=UC_HOOK_CODE:return original_hook_add(kind,callback,*args,**kwargs)
        def wrapped(u,pc,n,unused):
            if pc==ARENA+0x1008:
                fp=u.reg_read(UC_ARM64_REG_X29);frames=[]
                while ARENA<=fp<=ARENA+0x100000-16 and len(frames)<16:
                    nextfp,lr=struct.unpack('<QQ',u.mem_read(fp,16))
                    frames.append({'FP':fp,'next_FP':nextfp,'LR':lr,
                                   'LR_RVA':hex(lr-SCM)if SCM<=lr<SCM+len(image)else None})
                    if nextfp<=fp:break
                    fp=nextfp
                matched=[r for r in frames if r['LR']==SCM+0x3c40]
                assert len(matched)==1,frames
                methodfp=matched[0]['next_FP']
                ctx=struct.unpack('<4Q',u.mem_read(methodfp-0x20,32))
                x6=struct.unpack('<Q',u.mem_read(methodfp+0x18,8))[0]
                entrysp=u.reg_read(UC_ARM64_REG_SP)
                chunks=[(u.reg_read(UC_ARM64_REG_X29),16),(methodfp,16),
                        (methodfp-0x20,24),(methodfp+0x18,8)]
                observed.append({'entry_X24':hex(u.reg_read(UC_ARM64_REG_X24)),
                   'entry_X29':hex(u.reg_read(UC_ARM64_REG_X29)),
                   'entry_SP':hex(entrysp),
                   'entry_LR_RVA':hex(u.reg_read(UC_ARM64_REG_LR)-SCM),
                   'buffer':hex(u.reg_read(UC_ARM64_REG_X0)),
                   'bytes':u.reg_read(UC_ARM64_REG_X1),
                   'model_stack_low':hex(ARENA+0xf0000-0x4000),
                   'model_stack_high':hex(ARENA+0xf0000+0x100),
                   'stack_chunks':[{'address':hex(at),'bytes':n,
                       'hex':bytes(u.mem_read(at,n)).hex()}for at,n in chunks],
                   'SCM_method_FP':hex(methodfp),
                   'retained_X1_X2_X3_and_untouched_fourth_slot':[hex(x)for x in ctx],
                   'retained_X6':hex(x6),'frames':frames})
            callback(u,pc,n,unused)
            if pc==SCM+0x8e94:
                for reg,name in [(UC_ARM64_REG_X2,'X2'),(UC_ARM64_REG_X3,'X3'),(UC_ARM64_REG_X6,'X6')]:
                    u.reg_write(reg,fixture[name])
        return original_hook_add(kind,wrapped,*args,**kwargs)
    uc.hook_add=hook_add
    return uc

nodes=[n for n in ast.parse(source.read_text()).body
       if isinstance(n,(ast.ClassDef,ast.FunctionDef))and n.name in ['BudgetStop','run']]
assert len(nodes)==2
env=dict(globals());exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),env)
rows=[]
cases=[(command,full,0x1122334455667788)
       for command in [0x42000201,0x42000202]
       for full in [-0x300046,0xffcfffba,0x12345678ffcfffba]]
cases += [(0x42000202,-1,0),(0x42000202,-2,-13),(0x42000202,-2,0)]
for command,full,service in cases:
    fixture.update(X2=0x2233445566778899,X3=0x3344556677889900,X6=0x6677889900112233)
    observed.clear()
    r=env['run']('frame-retention-'+hex(command)+'-'+hex(full&mask),
                 command=command,transport=(full,),service=service)
    expected=0x8000000000000003 if full==-1 else \
        0x8000000000000014 if full==-2 and service==-13 else 0x8000000000000007
    assert len(observed)==1 and int(r['api_return'],16)==expected
    o=observed[0]
    assert o['entry_X24']==hex(full&mask)
    assert o['retained_X1_X2_X3_and_untouched_fourth_slot'][:3]==[
        hex(service&mask),hex(fixture['X2']),hex(fixture['X3'])]
    assert o['retained_X6']==hex(fixture['X6'])
    assert int(r['api_results'][0],16)==service&mask
    assert int(o['buffer'],16)==int(o['entry_SP'],16)+0xf8 and o['bytes']==72
    assert sum(x['bytes']for x in o['stack_chunks'])==64
    rows.append({'command':hex(command),'transport_X0_fixture':hex(full&mask),'observation':o,
                 'public_API_status':r['api_return'],
                 'public_API_results':r['api_results'],
                 'entry_X24_matches_full_X0':o['entry_X24']==hex(full&mask)})
out={'passed':True,'cases':len(rows),'original_instructions_unchanged':True,
     'native_operations':0,'source_runner_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
     'inspector_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
     'SCM_sha256':hashlib.sha256(raw).hexdigest(),'results':rows,
     'scope':'Original SCM/formatter replay with modeled secure response registers. Callback-entry registers and bounded model stack are observations, not native response recovery.'}
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items()if k!='results'},indent=2))
