"""Execute the captured AOP ready routine and model/revision helpers unchanged.

The PMIC byte-read boundary is modeled. Explicit model/revision/flag inputs
are test fixtures; this does not claim a native AOP-RAM or voltage measurement.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn.arm_const import *

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', type=Path, required=True)
p.add_argument('--aop-decoder', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
spec = importlib.util.spec_from_file_location('aop_decode', a.aop_decoder)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
elf = mod.Elf(a.image, mod.AOP_SHA)
ARENA, CTX, COMM, PERIPH, STACK, END = 0x30000000, 0x30001000, 0x30002000, 0x30003000, 0x3003f000, 0x10000000
def case(name, status, flag=1, model=73, revision=2, index=3, present=True, null=False, errors=0):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    pages, segs = set(), []
    for s in elf.segments:
        va = s['va'] - 0xb000000 if s['va'] in [0xb000000, 0xb0e0000] else s['va']
        segs.append((s, va))
        pages.update(range(va & ~4095, (va + s['memsz'] + 4095) & ~4095, 4096))
    for page in sorted(pages):
        u.mem_map(page, 4096)
    for s, va in segs:
        u.mem_write(va, elf.raw[s['offset']:s['offset'] + s['filesz']])
    u.mem_map(ARENA, 0x40000)
    u.mem_map(END, 4096)
    def w32(at, v): u.mem_write(at, struct.pack('<I', v))
    def r32(at): return struct.unpack('<I', u.mem_read(at, 4))[0]
    assert r32(0xe4b4) == r32(0xe4d8) and r32(0xe4b8) == r32(0xe4dc)
    u.mem_write(r32(0xe4b4), b'\1')
    w32(r32(0xe4b8) + 16, model)
    w32(r32(0xe4dc) + 20, revision)
    w32(CTX + 4, 0xe138c)
    w32(CTX + 8, 17)
    w32(CTX + 12, PERIPH)
    assert struct.unpack('<H', u.mem_read(0xe138e, 2))[0] == 8
    w32(COMM, 1)
    u.mem_write(COMM + 4, b'\1')
    u.mem_write(PERIPH + 3 * 28 + 12, struct.pack('<H', 0xc400))
    u.mem_write(PERIPH + 3 * 28 + 14, bytes([4 if present else 0, flag]))
    u.mem_write(ARENA, b'\xa5')
    regs = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]
    saved = [0x88000000 + i * 256 for i in range(len(regs))]
    for r, v in zip(regs, saved): u.reg_write(r, v)
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_LR, END | 1)
    for r, v in [(UC_ARM_REG_R0, CTX), (UC_ARM_REG_R1, COMM), (UC_ARM_REG_R2, index), (UC_ARM_REG_R3, 0 if null else ARENA)]: u.reg_write(r, v)
    calls = []
    def hook(uc, pc, size, data):
        if pc != 0xdd94: return
        sid, address, buffer = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)
        assert sid == 1 and address == 0xc408 and uc.reg_read(UC_ARM_REG_R3) == 0
        fail = len(calls) < errors
        if not fail:
            uc.mem_write(buffer, bytes([status]))
        calls.append({'sid': sid, 'address': hex(address), 'status': status, 'modeled_error': fail})
        uc.reg_write(UC_ARM_REG_R0, 0x80 if fail else 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(0xe193, END, count=200000)
    assert u.reg_read(UC_ARM_REG_PC) == END and u.reg_read(UC_ARM_REG_SP) == STACK
    assert [u.reg_read(r) for r in regs] == saved
    ret, value = u.reg_read(UC_ARM_REG_R0), bytes(u.mem_read(ARENA, 1))[0]
    if index >= 17 or not present:
        assert ret == 0x40 and not calls and value == 0xa5
    elif null:
        assert ret == 2 and not calls
    elif errors >= 2:
        assert ret == 0x80 and value == 0 and len(calls) == 2
    else:
        mask = 4 if flag and ((model in [30, 31] and revision < 3) or (model in [34, 36, 38, 39] and revision < 2)) else 0x80
        assert ret == 0 and value == int(status & mask == mask) and len(calls) == min(errors + 1, 2)
    return {'name': name, 'model': model, 'revision': revision, 'flag': flag, 'raw_status': status, 'result': value, 'status_code': ret, 'calls': calls}

cases = []
for flag in [0, 1]:
    for raw in [3, 0x83, 4, 0x80, 0x87]:
        cases.append(case('native-model73-flag%d-status%x' % (flag, raw), raw, flag=flag))
for model, revision, raw in [(30, 2, 4), (30, 3, 0x80), (34, 1, 4), (34, 2, 0x80)]:
    cases.append(case('legacy-mask-%d-rev%d' % (model, revision), raw, model=model, revision=revision))
cases += [case('read-retry-once', 0x83, errors=1), case('read-fails-twice', 0x83, errors=2), case('out-of-range', 3, index=17), case('missing-peripheral', 3, present=False), case('null-output', 3, null=True)]
# The target-voltage routine reads table+0x12 (=0x40), not offsets42/43.
# Min0/step1000 are explicit unified-map fixtures; byte transport is modeled.
def voltage_case(name, code=1800, error=0, null=False, index=3, present=True, unified=True):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    pages=set();segs=[]
    for seg in elf.segments:
        va=seg['va']-0xb000000 if seg['va'] in [0xb000000,0xb0e0000] else seg['va']
        segs.append((seg,va));pages.update(range(va&~4095,(va+seg['memsz']+4095)&~4095,4096))
    for page in sorted(pages):u.mem_map(page,4096)
    for seg,va in segs:u.mem_write(va,elf.raw[seg['offset']:seg['offset']+seg['filesz']])
    u.mem_map(ARENA,0x40000);u.mem_map(END,4096)
    def w32(at,value):u.mem_write(at,struct.pack('<I',value))
    def r32(at):return struct.unpack('<I',u.mem_read(at,4))[0]
    w32(CTX+4,0xe138c);w32(CTX+8,17);w32(CTX+12,PERIPH);w32(COMM,1)
    assert struct.unpack('<H',u.mem_read(0xe138c+0x12,2))[0]==0x40
    pr=PERIPH+3*28;w32(pr,0);w32(pr+4,2000000);w32(pr+8,1000)
    u.mem_write(pr+12,struct.pack('<H',0xc400));u.mem_write(pr+14,bytes([4 if present else 0]));u.mem_write(pr+16,bytes([int(unified)]))
    w32(ARENA,0xa5a5a5a5)
    regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    saved=[0x88000000+i*256 for i in range(len(regs))]
    for r,v in zip(regs,saved):u.reg_write(r,v)
    u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,END|1)
    for r,v in [(UC_ARM_REG_R0,CTX),(UC_ARM_REG_R1,COMM),(UC_ARM_REG_R2,index),(UC_ARM_REG_R3,0 if null else ARENA)]:u.reg_write(r,v)
    calls=[]
    def hook(uc,pc,size,data):
        if pc!=0xdef8:return
        sid,address,length,buffer=[uc.reg_read(r)for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
        assert sid==1 and address==0xc440 and length==2
        assert r32(uc.reg_read(UC_ARM_REG_SP))==0
        if not error:uc.mem_write(buffer,struct.pack('<H',code))
        calls.append({'sid':sid,'address':hex(address),'length':length,'code':code,'modeled_error':error})
        uc.reg_write(UC_ARM_REG_R0,error);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0xe2b9,END,count=200000)
    assert u.reg_read(UC_ARM_REG_PC)==END and u.reg_read(UC_ARM_REG_SP)==STACK
    assert [u.reg_read(r)for r in regs]==saved
    ret,value=u.reg_read(UC_ARM_REG_R0),r32(ARENA)
    expected=0x40 if index>=17 or not present else 2 if null else 4 if not unified else error
    assert ret==expected
    if expected:assert value==0xa5a5a5a5
    else:assert value==code*1000 and len(calls)==1
    assert len(calls)==int(expected not in [0x40,2,4])
    return {'name':name,'status_code':ret,'output':value,'calls':calls}
voltage_cases=[voltage_case('captured-target1800'),voltage_case('zero',code=0),voltage_case('alternate',code=2000),voltage_case('read-error',error=0x80),voltage_case('null',null=True),voltage_case('invalid-index',index=17),voltage_case('missing',present=False),voltage_case('not-unified',unified=False)]
out={'image_sha256':elf.sha,'original_functions':['ready@0xe192','model@0xe49c','revision@0xe4bc','target_voltage@0xe2b8'],
     'ready_cases_passed':len(cases),'target_voltage_cases_passed':len(voltage_cases),'cases':cases,'voltage_cases':voltage_cases,
     'observed_native87_ready_result':True,'target_voltage_register_offset':'0x40',
     'ready_mask_for_model73':'0x80','modeled_boundaries':['PMIC byte-read@0xdd94','PMIC byte-array-read@0xdef8'],
     'offset42_43_precise_semantics_established':False,
     'limits':['No live AOP RAM access or electrical voltage measurement.','Unified voltage min0/step1000 are explicit fixture inputs.','The extra42/43 bytes are preserved as raw observed state; these routines do not establish their precise meaning.']}
a.output.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'ready_cases':len(cases),'target_voltage_cases':len(voltage_cases),'observed87_decodes_ready':True,'target_voltage_reads_offset':'0x40'}))
