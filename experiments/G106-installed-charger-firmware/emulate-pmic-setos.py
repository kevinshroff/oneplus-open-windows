"""Run actual installed-reference PMIC SetOS instructions with modeled SDAM.

Also execute the original OEM charger loader/helper across the real protocol
table into that PMIC method. All hardware, PIL and mount boundaries are models.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--pmic', type=Path, required=True)
p.add_argument('--charger', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
pmic_raw, charger_raw = a.pmic.read_bytes(), a.charger.read_bytes()
sha = lambda data: hashlib.sha256(data).hexdigest()
assert sha(pmic_raw) == 'd8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
assert sha(charger_raw) == '5722eeb57dc7d25968829f96a4e5f5b4c9664e0d458e92642e948d59591f4b6e'
PB, ARENA, END, LOCATE, PIL = 0x1000000, 0x30000000, 0x10000000, 0x10001000, 0x10002000
pmic = pefile.PE(data=pmic_raw)
original = pmic.get_memory_mapped_image()
pmic.relocate_image(PB)
pmic_image = pmic.get_memory_mapped_image()
assert pmic_image[0x25b08:0x25c70] == original[0x25b08:0x25c70]
assert struct.unpack_from('<Q', pmic_image, 0x39dc8+0x188)[0] == PB+0x25b08
charger = pefile.PE(data=charger_raw).get_memory_mapped_image()
SCHG = bytes.fromhex('6ee96aae3f48ae429cc19fac1b584728')
PILGUID = charger[0x21268:0x21278]
ERROR, INVALID = 0x8000000000000007, 0x8000000000000002
SAVED = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
         UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
         UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
         UC_ARM64_REG_X28, UC_ARM64_REG_X29]


def run(role=0, initial=0, failure=None, mismatch=False, integrated=False,
        mount_status=0, pil_status=0, guard=1):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for base, data in ((0, charger), (PB, pmic_image)):
        u.mem_map(base, (len(data)+4095) & ~4095)
        u.mem_write(base, data)
    u.mem_map(ARENA, 0x40000)
    u.mem_map(END, 0x3000)

    def put(at, value):
        u.mem_write(at, struct.pack('<Q', value))

    put(0x217b0, ARENA)
    put(ARENA+0x140, LOCATE)
    put(ARENA+0x1000+8, PIL)
    u.mem_write(0x214e0, bytes([guard]))
    stack = ARENA+0x3fff0
    u.reg_write(UC_ARM64_REG_SP, stack)
    u.reg_write(UC_ARM64_REG_LR, END)
    u.reg_write(UC_ARM64_REG_X0, role)
    for i, reg in enumerate(SAVED):
        u.reg_write(reg, 0x8800000000000000+i*256)
    preserved = [u.reg_read(reg) for reg in SAVED]
    events, cell, read_count = [], initial, 0

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def wide(at):
        raw = bytes(u.mem_read(at, 128))
        end = next(i for i in range(0, len(raw), 2) if raw[i:i+2] == b'\0\0')
        return raw[:end].decode('utf-16le')

    def hook(uc, pc, size, unused):
        nonlocal cell, read_count
        if pc in (PB+0x163e0, PB+0x162d4):
            args = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                                UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            assert args == [0, 15, 30, 1]
            pointer = uc.reg_read(UC_ARM64_REG_X4)
            assert ARENA <= pointer < ARENA+0x40000
            if pc == PB+0x163e0:
                phase = 'initial_read' if read_count == 0 else 'readback'
                read_count += 1
                events.append({'call': phase, 'logical_args': args})
                if failure == phase:
                    ret(1)
                else:
                    value = cell ^ (2 if mismatch and phase == 'readback' else 0)
                    uc.mem_write(pointer, bytes([value]))
                    ret(0)
            else:
                value = bytes(uc.mem_read(pointer, 1))[0]
                events.append({'call': 'write', 'logical_args': args, 'value': value})
                if failure == 'write':
                    ret(1)
                else:
                    cell = value
                    ret(0)
        elif pc == LOCATE:
            value = bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0), 16))
            if value == SCHG:
                events.append({'call': 'LocateSCHG_actual_table'})
                put(uc.reg_read(UC_ARM64_REG_X2), PB+0x39dc8)
            elif value == PILGUID:
                events.append({'call': 'LocatePIL'})
                put(uc.reg_read(UC_ARM64_REG_X2), ARENA+0x1000)
            else:
                raise AssertionError(value.hex())
            ret(0)
        elif pc == 0x8738:
            events.append({'call': 'MountFatPartition', 'name': wide(uc.reg_read(UC_ARM64_REG_X0))})
            ret(mount_status)
        elif pc == PIL:
            events.append({'call': 'PIL', 'name': wide(uc.reg_read(UC_ARM64_REG_X0))})
            ret(pil_status)
        elif pc in (0x6a34, 0xdfa0, 0xdfac, 0xdfb4,
                    PB+0x3f94, PB+0x3fa0, PB+0x3fa8, PB+0x4268, PB+0x6f40):
            ret(0)

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(0x13094 if integrated else PB+0x25b08, END, count=100000)
    assert u.reg_read(UC_ARM64_REG_PC) == END and u.reg_read(UC_ARM64_REG_SP) == stack
    assert [u.reg_read(reg) for reg in SAVED] == preserved
    return {'selector': role, 'initial_byte': initial, 'final_byte': cell,
            'status': hex(u.reg_read(UC_ARM64_REG_X0)), 'events': events}


count, exhaustive, examples = 0, [], []
for role in (0, 1):
    for value in range(256):
        row = run(role, value)
        assert int(row['status'], 16) == 0 and row['final_byte'] == (value & 0xe) | role
        assert [e['call'] for e in row['events']] == ['initial_read', 'write', 'readback']
        exhaustive.append([role, value, row['final_byte']])
        count += 1
        if value == 255:
            examples.append({'case': 'all-bits-set', **row})
    for phase, calls in [('initial_read', ['initial_read']), ('write', ['initial_read', 'write']),
                         ('readback', ['initial_read', 'write', 'readback'])]:
        row = run(role, 255, failure=phase)
        assert int(row['status'], 16) == ERROR and [e['call'] for e in row['events']] == calls
        examples.append({'case': 'failure-'+phase, **row})
        count += 1
    row = run(role, 255, mismatch=True)
    assert int(row['status'], 16) == 0
    examples.append({'case': 'readback-value-not-compared', **row})
    count += 1
for role in (2, 0xffffffff):
    row = run(role, 255)
    assert int(row['status'], 16) == INVALID and not row['events'] and row['final_byte'] == 255
    examples.append({'case': 'invalid-selector', **row})
    count += 1
normal = ['LocatePIL', 'LocateSCHG_actual_table', 'initial_read', 'write', 'readback', 'MountFatPartition', 'PIL']
for name, kwargs, status, calls in [
    ('integrated-success', {}, 0, normal),
    ('integrated-read-fail', {'failure': 'initial_read'}, ERROR, normal[:3]),
    ('integrated-write-fail', {'failure': 'write'}, ERROR, normal[:4]),
    ('integrated-readback-fail', {'failure': 'readback'}, ERROR, normal[:5]),
    ('integrated-mount-fail-continues', {'mount_status': ERROR}, 0, normal),
    ('integrated-pil-fail', {'pil_status': ERROR}, ERROR, normal),
    ('integrated-guard-off', {'guard': 0}, 0, []),
]:
    row = run(initial=255, integrated=True, **kwargs)
    assert int(row['status'], 16) == status and [e['call'] for e in row['events']] == calls
    for event in row['events']:
        if event['call'] == 'MountFatPartition':
            assert event['name'] == 'modem_a'
        elif event['call'] == 'PIL':
            assert event['name'] == 'FULL_ADSP'
    examples.append({'case': name, **row})
    count += 1
result = {
    'passed': True, 'cases': count, 'exhaustive_byte_cases': len(exhaustive),
    'exhaustive_results_sha256': sha(json.dumps(exhaustive, separators=(',', ':')).encode()),
    'PMIC_sha256': sha(pmic_raw), 'charger_sha256': sha(charger_raw),
    'original_SetOS_instruction_bytes_unmodified': True, 'normal_PE_relocations_applied': True,
    'actual_SCHG_protocol_table_used_in_integrated_cases': True,
    'native_operations': 0,
    'modeled_boundaries': ['SDAM read/write wrappers at PMIC163e0/162d4', 'UEFI LocateProtocol',
                          'MountFatPartition', 'PIL method', 'logging'],
    'observations': ['SetOS writes (old_byte & 0x0e) | selector, clearing the high nibble.',
                     'All SDAM wrapper calls use logical PMIC0, bank15, offset30, length1.',
                     'Readback status is checked; a successful read with a mismatching value still returns success.'],
    'limits': ['Selector enum meanings and physical SDAM address are not established here.',
               'No charger enable, PMIC register, ADSP, modem_a or native firmware operation occurs.',
               'These are code-behavior results under explicit hardware-boundary models.'],
    'representative_cases': examples,
}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({k: result[k] for k in ('passed', 'cases', 'exhaustive_byte_cases', 'native_operations')}))
