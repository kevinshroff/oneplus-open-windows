"""Validate installed PMIC bypass control flow under explicit call models.

No PMIC operation executes. Stock dead-battery internals are static REA
evidence; only its installed immediate-return replacement executes here.
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
p.add_argument('--stock', type=Path, required=True)
p.add_argument('--installed', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
stock, installed = a.stock.read_bytes(), a.installed.read_bytes()
sha = lambda value: hashlib.sha256(value).hexdigest()
assert sha(stock) == 'bcee17662d48ce610eb3e895107f6fb2afc962d8fe04429742e1925ceece2b0b'
assert sha(installed) == 'd8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
images = {name: pefile.PE(data=raw).get_memory_mapped_image()
          for name, raw in [('stock', stock), ('installed', installed)]}
assert images['stock'][0x25b08:0x25c70] == images['installed'][0x25b08:0x25c70]
ARENA, END = 0x30000000, 0x10000000
EXPECTED = [[0, 0x729a, 1], [4, 0x8a40, 1], [13, 0x4577, 0],
            [0, 0x72b3, 1], [1, 0xc4a0, 0], [0, 0x7296, 0],
            [0, 0x0871, 9], [0, 0x72b3, 1], [7, 0x2641, 2]]


def run(which, entry, write_failure=-1, failed_call=0):
    image = images[which]
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image)+4095) & ~4095)
    u.mem_write(0, image)
    u.mem_map(ARENA, 0x10000)
    u.mem_map(END, 4096)
    stack = ARENA+0xfff0
    u.reg_write(UC_ARM64_REG_SP, stack)
    u.reg_write(UC_ARM64_REG_LR, END)
    events = []

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def hook(uc, pc, size, user):
        if pc == 0xdeb4:
            values = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            index = len(events)
            events.append({'call': 'modeled_write_helper', 'args': values})
            ret(1 << index if index == write_failure else 0)
        elif pc in (0x18570, 0x18b98, 0x17198, 0x18a7c):
            events.append({'call': hex(pc)})
            ret(1 if pc == failed_call else 0)

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(entry, END, count=10000)
    assert u.reg_read(UC_ARM64_REG_PC) == END and u.reg_read(UC_ARM64_REG_SP) == stack
    return {'image': which, 'entry': hex(entry), 'write_failure': write_failure,
            'failed_call': hex(failed_call), 'result': hex(u.reg_read(UC_ARM64_REG_X0)), 'events': events}


rows = []
for failure in range(-1, 9):
    row = run('stock', 0x184b4, write_failure=failure)
    assert [event['args'] for event in row['events']] == EXPECTED
    expected = (1 << failure) if failure in (4, 6, 7, 8) else 0
    assert int(row['result'], 16) == expected
    rows.append(row)
for entry in (0x184b4, 0x18578):
    row = run('installed', entry)
    assert not row['events'] and int(row['result'], 16) == 0
    rows.append(row)
for image in ('stock', 'installed'):
    for failed in (0, 0x18570, 0x18b98, 0x17198, 0x18a7c):
        row = run(image, 0x42c8, failed_call=failed)
        calls = [event['call'] for event in row['events']]
        assert calls == (['0x18570', '0x18b98', '0x17198', '0x18a7c'] if image == 'stock'
                         else ['0x18570', '0x18a7c'])
        expected = 0x8000000000000007 if failed and (image == 'stock' or failed in (0x18570, 0x18a7c)) else 0
        assert int(row['result'], 16) == expected
        rows.append(row)
result = {'passed': True, 'cases': len(rows), 'stock_sha256': sha(stock),
          'installed_sha256': sha(installed), 'original_ARM64_unmodified': True,
          'SetOS_instruction_bytes_identical': True, 'native_operations': 0,
          'modeled_boundaries': ['write helper deb4', 'init callees18570/18b98/17198/18a7c'],
          'observations': ['Installed184b4 and18578 return0 without executing their old bodies.',
                           'Installed42c8 calls18570/18a7c but skips18b98/17198.',
                           'Stock184b4 issues nine write-helper calls; only four return values reach its result.'],
          'limits': ['No register meaning, physical ownership or permission is established by the write-call model.',
                     'The stock18578 dead-battery body is not dynamically executed here.',
                     'These patches must not be undone solely from these software observations.'],
          'results': rows}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key: result[key] for key in ('passed', 'cases', 'native_operations')}))
