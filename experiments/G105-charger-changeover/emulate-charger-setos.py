"""Execute the original OEM SetOS helper and its caller with UEFI models.

Only software argument, cache, ordering and error behavior is established.
The modeled SCHG method performs no PMIC, charger or DSP operation.
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
p.add_argument('--image', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
raw = a.image.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == '5722eeb57dc7d25968829f96a4e5f5b4c9664e0d458e92642e948d59591f4b6e'
pe = pefile.PE(data=raw)
assert pe.FILE_HEADER.Machine == 0xaa64 and pe.OPTIONAL_HEADER.ImageBase == 0
image = pe.get_memory_mapped_image()
ARENA, END, LOCATE, PIL, SETOS = 0x30000000, 0x10000000, 0x10001000, 0x10002000, 0x10003000
SCHG_GUID = bytes.fromhex('6ee96aae3f48ae429cc19fac1b584728')
PIL_GUID = image[0x21268:0x21278]
assert image[0x210c8:0x210d8] == SCHG_GUID
ERROR, NOT_FOUND, INVALID = 0x8000000000000007, 0x800000000000000e, 0x8000000000000002
SAVED = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
         UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
         UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
         UC_ARM64_REG_X28, UC_ARM64_REG_X29]


def run(entry, role=0, *, cached=False, schg_status=0, schg_present=True,
        method_status=0, enabled=1, pil_locate_status=0, mount_status=0, pil_status=0):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image)+4095) & ~4095)
    u.mem_write(0, image)
    u.mem_map(ARENA, 0x40000)
    u.mem_map(END, 0x4000)

    def put(at, value):
        u.mem_write(at, struct.pack('<Q', value))

    put(0x217b0, ARENA)
    put(ARENA+0x140, LOCATE)
    put(ARENA+0x1000+8, PIL)
    put(ARENA+0x2000+0x188, SETOS)
    put(0x21f20, ARENA+0x2000 if cached else 0)
    u.mem_write(0x214e0, bytes([enabled]))
    stack = ARENA+0x3fff0
    u.reg_write(UC_ARM64_REG_SP, stack)
    u.reg_write(UC_ARM64_REG_LR, END)
    u.reg_write(UC_ARM64_REG_X0, role)
    for i, reg in enumerate(SAVED):
        u.reg_write(reg, 0x8800000000000000+i*256)
    before = [u.reg_read(reg) for reg in SAVED]
    events = []

    def ret(status):
        u.reg_write(UC_ARM64_REG_X0, status)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def wide(at):
        data = bytes(u.mem_read(at, 128))
        end = next(i for i in range(0, len(data), 2) if data[i:i+2] == b'\0\0')
        return data[:end].decode('utf-16le')

    def hook(uc, pc, size, user):
        if pc == LOCATE:
            guid = bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0), 16))
            if guid == SCHG_GUID:
                events.append({'call': 'LocateSCHG'})
                put(uc.reg_read(UC_ARM64_REG_X2), ARENA+0x2000 if schg_present else 0)
                ret(schg_status)
            elif guid == PIL_GUID:
                events.append({'call': 'LocatePIL'})
                put(uc.reg_read(UC_ARM64_REG_X2), ARENA+0x1000 if pil_locate_status == 0 else 0)
                ret(pil_locate_status)
            else:
                raise AssertionError('Unexpected protocol GUID: '+guid.hex())
        elif pc == SETOS:
            events.append({'call': 'SCHG_slot_0x188', 'selector': uc.reg_read(UC_ARM64_REG_X0)})
            ret(method_status)
        elif pc == 0x8738:
            events.append({'call': 'MountFatPartition', 'name': wide(uc.reg_read(UC_ARM64_REG_X0))})
            ret(mount_status)
        elif pc == PIL:
            events.append({'call': 'PIL_slot_8', 'name': wide(uc.reg_read(UC_ARM64_REG_X0))})
            ret(pil_status)
        elif pc in (0x6a34, 0xdfa0, 0xdfac, 0xdfb4):
            ret(0)

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(entry, END, count=100000)
    assert u.reg_read(UC_ARM64_REG_PC) == END
    assert u.reg_read(UC_ARM64_REG_SP) == stack
    assert [u.reg_read(reg) for reg in SAVED] == before
    return {'entry': hex(entry), 'role': role, 'cached': cached,
            'result': hex(u.reg_read(UC_ARM64_REG_X0)), 'events': events}


rows = []


def check(name, kwargs, status, calls):
    row = run(**kwargs)
    assert int(row['result'], 16) == status, (name, row)
    assert [v['call'] for v in row['events']] == calls, (name, row)
    for event in row['events']:
        if event['call'] == 'SCHG_slot_0x188':
            assert event['selector'] == kwargs.get('role', 0)
        elif event['call'] == 'MountFatPartition':
            assert event['name'] == 'modem_a'
        elif event['call'] == 'PIL_slot_8':
            assert event['name'] == 'FULL_ADSP'
    rows.append({'name': name, **row})


for role in (0, 1):
    check('fresh-selector-'+str(role), dict(entry=0xfecc, role=role), 0,
          ['LocateSCHG', 'SCHG_slot_0x188'])
    check('cached-selector-'+str(role), dict(entry=0xfecc, role=role, cached=True), 0,
          ['SCHG_slot_0x188'])
for role in (2, 0xffffffff):
    check('invalid-selector-'+str(role), dict(entry=0xfecc, role=role), INVALID, [])
check('lookup-error-normalized', dict(entry=0xfecc, schg_status=NOT_FOUND), ERROR, ['LocateSCHG'])
check('lookup-success-null', dict(entry=0xfecc, schg_present=False), ERROR, ['LocateSCHG'])
check('method-error-propagated', dict(entry=0xfecc, method_status=NOT_FOUND), NOT_FOUND,
      ['LocateSCHG', 'SCHG_slot_0x188'])
check('cached-method-error', dict(entry=0xfecc, cached=True, method_status=NOT_FOUND), NOT_FOUND,
      ['SCHG_slot_0x188'])
normal = ['LocatePIL', 'LocateSCHG', 'SCHG_slot_0x188', 'MountFatPartition', 'PIL_slot_8']
check('loader-guard-off', dict(entry=0x13094, enabled=0), 0, [])
check('loader-pil-lookup-error', dict(entry=0x13094, pil_locate_status=NOT_FOUND), NOT_FOUND, ['LocatePIL'])
check('loader-schg-lookup-error', dict(entry=0x13094, schg_status=NOT_FOUND), ERROR, ['LocatePIL', 'LocateSCHG'])
check('loader-setos-error', dict(entry=0x13094, method_status=NOT_FOUND), NOT_FOUND,
      ['LocatePIL', 'LocateSCHG', 'SCHG_slot_0x188'])
check('loader-success', dict(entry=0x13094), 0, normal)
check('loader-mount-failure-continues', dict(entry=0x13094, mount_status=NOT_FOUND), 0, normal)
check('loader-pil-load-error', dict(entry=0x13094, pil_status=NOT_FOUND), NOT_FOUND, normal)
result = {
    'passed': True, 'cases': len(rows), 'artifact_sha256': sha,
    'original_ARM64_unmodified': True, 'native_operations': 0,
    'functions_executed': ['0xfecc', '0x13094'],
    'modeled_boundaries': ['UEFI LocateProtocol', 'SCHG method +0x188',
                          'MountFatPartition', 'PIL method +8', 'logging'],
    'limits': ['Selector enum names and SCHG method hardware effects remain unproved.',
               'ChargerLibTarget_Init selector 1 is static REA evidence; its whole body is not executed here.',
               'No native firmware, charger, ADSP or modem_a access/write occurs.',
               'Exact current phone firmware byte identity remains a separate check.'],
    'results': rows,
}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({k: result[k] for k in ('passed', 'cases', 'original_ARM64_unmodified', 'native_operations')}))
