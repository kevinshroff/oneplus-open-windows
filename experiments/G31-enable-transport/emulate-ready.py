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
    for raw in [3, 0x83, 4, 0x80]:
        cases.append(case('native-model73-flag%d-status%x' % (flag, raw), raw, flag=flag))
for model, revision, raw in [(30, 2, 4), (30, 3, 0x80), (34, 1, 4), (34, 2, 0x80)]:
    cases.append(case('legacy-mask-%d-rev%d' % (model, revision), raw, model=model, revision=revision))
cases += [case('read-retry-once', 0x83, errors=1), case('read-fails-twice', 0x83, errors=2), case('out-of-range', 3, index=17), case('missing-peripheral', 3, present=False), case('null-output', 3, null=True)]
out = {'image_sha256': elf.sha, 'original_functions': ['ready@0xe192', 'model@0xe49c', 'revision@0xe4bc'],
       'passed': len(cases), 'cases': cases, 'native_model_basis': 'G25 double-read SMEM index1 subtype73 and revision-peripheral model49hex',
       'result': 'Original routine uses status bit7 for model73, for either peripheral flag.',
       'modeled_boundary': 'PMIC byte-read@0xdd94 only; no original read-transport execution is claimed',
       'limits': ['Internal model/revision/peripheral data are explicit fixtures, not a live AOP RAM read.', 'No native MMIO or electrical measurement occurs.']}
a.output.write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps({'passed': len(cases), 'original_functions': 3, 'native_model73_ready_mask': '0x80'}))
