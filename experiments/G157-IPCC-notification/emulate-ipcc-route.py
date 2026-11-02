"""Replay original GLINK -> IPCC instructions with explicit OS/MMIO models."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ipcc', type=Path, required=True)
parser.add_argument('--glink', type=Path, required=True)
parser.add_argument('--boot-fdt', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
assert not args.output.exists(), 'Preserve the previous replay'
sha = lambda data: hashlib.sha256(data).hexdigest()
ipcc = args.ipcc.read_bytes()
glink = args.glink.read_bytes()
fdt_raw = args.boot_fdt.read_bytes()
assert sha(ipcc) == '595e7b2158c36ece09629982516645afa1fdd8604375c291122eae814ea128aa'
assert sha(glink) == '282e62e472097725ad35ce474c4ac29debac10ffafbd467f328ff51b18cb51e6'
assert sha(fdt_raw) == 'f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29'
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fdtree import Fdt
fdt = Fdt(fdt_raw)
edge = '/sw/glink/xport-smem-config/edge-01'
assert fdt.cells(edge, 'remote-host') == [2]
cid, signal = fdt.cells(edge, 'irq-out')
assert [cid, signal] == [3, 0]

IPCC, GLINK, ARENA, END, VIRTUAL = 0x10000000, 0x20000000, 0x30000000, 0x50000000, 0x60000000
images = [(IPCC, pefile.PE(data=ipcc).get_memory_mapped_image(ImageBase=IPCC)),
          (GLINK, pefile.PE(data=glink).get_memory_mapped_image(ImageBase=GLINK))]
registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
             UC_ARM64_REG_X4, UC_ARM64_REG_X5]
cases = []


def run(name, *, lazy=True, mapping=False, protocol=0, target=3, low=0, high=None,
        direct=False, null=False, locate_failure=False, allocation_failure=False):
    if high is None:
        high = low
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for base, image in images:
        u.mem_map(base, (len(image) + 4095) & ~4095)
        u.mem_write(base, image)
    u.mem_map(ARENA, 0x100000)
    u.mem_map(END, 0x1000)
    u.mem_map(0x400000, 0x100000)
    u.mem_map(VIRTUAL, 0x100000)
    u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
    events, stores = [], []
    heap = ARENA + 0x10000
    protocol_interface = IPCC + 0xc0b8
    context_out = GLINK + 0xd570
    bs, locate, dal_handle, dal_vtable, mapper = [ARENA + x for x in [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]]
    params = ARENA + 0x6000

    def q(at, value):
        u.mem_write(at, struct.pack('<Q', value))

    def d(at, value):
        u.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def ret(value=0):
        u.reg_write(UC_ARM64_REG_X0, value & 0xffffffffffffffff)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def call(pc, values):
        u.reg_write(UC_ARM64_REG_SP, ARENA + 0xf0000)
        u.reg_write(UC_ARM64_REG_LR, END)
        for reg, value in zip(registers, values):
            u.reg_write(reg, value)
        u.emu_start(pc, END, count=300000)
        assert u.reg_read(UC_ARM64_REG_PC) == END, name
        return u.reg_read(UC_ARM64_REG_X0)

    def hook(cpu, pc, size, unused):
        nonlocal heap
        z = [u.reg_read(reg) for reg in registers]
        if pc == IPCC + 0x8228:
            assert z[0] == 0x02000070
            if mapping:
                q(z[1], dal_handle)
            events.append({'model': 'DAL device attach', 'result': 0 if mapping else 1})
            ret(0 if mapping else 1)
        elif pc == mapper:
            assert z[0] == dal_handle and z[1] == 0x400000
            q(z[2], VIRTUAL)
            events.append({'model': 'DAL MapIO', 'physical': hex(z[1]), 'virtual': hex(VIRTUAL)})
            ret()
        elif pc == IPCC + 0x1fe8:
            assert z[0] == 32
            value = 0 if allocation_failure else heap
            heap += 0x100
            events.append({'model': 'allocator', 'bytes': z[0], 'failed': allocation_failure})
            ret(value)
        elif pc == IPCC + 0x24ac:
            events.append({'model': 'RX attachment', 'context': hex(z[0])})
            ret()
        elif pc == IPCC + 0x1fbc:
            ret()  # logging has no effect on the write/result under test
        elif pc == locate:
            needle = bytes(u.mem_read(z[0], 16))
            assert needle.hex() == 'd78a8552168b37419c64dfe04d942e80' and z[1] == 0
            events.append({'model': 'LocateProtocol', 'GUID': needle.hex(), 'failed': locate_failure})
            if not locate_failure:
                q(z[2], protocol_interface)
            ret(0x800000000000000e if locate_failure else 0)
        elif pc == IPCC + 0x1f14:
            events.append({'original_trigger_args': [hex(z[0]), z[1], z[2], z[3]]})

    def memory_write(cpu, access, address, size, value, unused):
        if 0x400000 <= address < 0x500000 or VIRTUAL <= address < VIRTUAL + 0x100000:
            stores.append({'address': hex(address), 'bytes': size, 'value': hex(value)})

    u.hook_add(UC_HOOK_CODE, hook)
    u.hook_add(UC_HOOK_MEM_WRITE, memory_write)
    q(dal_handle + 8, dal_vtable)
    q(dal_vtable + 0x58, mapper)
    q(GLINK + 0xd380, bs)
    q(bs + 0x140, locate)
    q(GLINK + 0xd578, 0)
    q(context_out, 0)
    d(params, target)
    d(params + 4, low)

    # Real descriptor/root initialization; only DAL attach/MapIO is modeled.
    call(IPCC + 0x2b24, [IPCC + 0xc260])
    descriptor = IPCC + 0xc130 + 56 * protocol
    if protocol < 4:
        expected_base = (VIRTUAL if mapping else 0x400000) + 0x8000 + protocol * 0x40000
        assert struct.unpack('<Q', u.mem_read(descriptor + 0x18, 8))[0] == expected_base
    else:
        expected_base = None
    if not lazy or direct:
        q(GLINK + 0xd578, protocol_interface)
        attached = call(IPCC + 0x14a0, [context_out, protocol])
        context = struct.unpack('<Q', u.mem_read(context_out, 8))[0]
        if allocation_failure or protocol >= 4:
            assert attached != 0 and context == 0 and not stores
            cases.append({'case': name, 'attach_result': hex(attached), 'MMIO_writes': stores, 'events': events})
            return
        assert attached == 0 and context
    if null:
        context = 0
    else:
        context = struct.unpack('<Q', u.mem_read(context_out, 8))[0]
    if direct:
        result = call(IPCC + 0x14b0, [context, target, low, high])
    else:
        # Original lazy GLINK wrapper invokes the actual relocated IPCC table.
        assert not null and protocol == 0
        if locate_failure or allocation_failure:
            # This legacy wrapper does not check failed lookup/attach before
            # dereferencing. Qualify those failures through the public method,
            # never emulate an invented safe wrapper or use it natively.
            raise AssertionError('Use direct public API refusal cases for null/failure')
        result = call(GLINK + 0x4e58, [params])
    good = not null and protocol < 4 and target < 27 and low <= high < (4 if protocol == 0 else 32)
    expected = [{'address': hex(expected_base + 0xc), 'bytes': 4,
                 'value': hex((target << 16) | i)} for i in range(low, high + 1)] if good else []
    assert stores == expected, (name, stores, expected)
    assert result == (0 if good else 0xfffffffd), (name, hex(result))
    cases.append({'case': name, 'protocol': protocol, 'target_CID': target,
                  'signal_low': low, 'signal_high': high, 'lazy_Glink': lazy and not direct,
                  'mapping_model': mapping, 'result': hex(result),
                  'MMIO_writes': stores, 'events': events})


for mapping in [False, True]:
    for lazy in [False, True]:
        run('captured-ADSP-' + ('mapped' if mapping else 'identity') + ('-lazy' if lazy else '-attached'),
            mapping=mapping, lazy=lazy, target=cid, low=signal)
for name, kw in [
    ('invalid-null', {'null': True}), ('invalid-CID', {'target': 27}),
    ('invalid-signal', {'low': 4}), ('invalid-reversed-range', {'low': 2, 'high': 1}),
    ('last-valid-CID-signal', {'target': 26, 'low': 3}),
    ('protocol1-range', {'protocol': 1, 'target': 3, 'low': 0, 'high': 2}),
    ('protocol2-range', {'protocol': 2, 'target': 6, 'low': 30, 'high': 31}),
    ('protocol3-last-signal', {'protocol': 3, 'target': 2, 'low': 31}),
    ('attach-unsupported-protocol', {'protocol': 4}),
    ('attach-allocation-failure', {'allocation_failure': True}),
]:
    run(name, direct=True, lazy=False, **kw)
result = {'passed': True, 'cases': len(cases), 'native_operations': 0,
          'unmodified_original_instructions_executed': True,
          'IPCC_PE_sha256': sha(ipcc), 'GLINK_PE_sha256': sha(glink),
          'boot_FDT_sha256': sha(fdt_raw), 'captured_ADSP_irq_out': [cid, signal],
          'observed_original_physical_doorbell': {'address': '0x40800c', 'bytes': 4, 'value': '0x30000'},
          'models': ['DAL device attach/MapIO', 'allocator', 'RX attachment', 'UEFI LocateProtocol',
                     'logging', 'MMIO as ordinary emulated RAM'],
          'limits': ['No native MMIO, DSP request, FIFO write, reset or driver installation.',
                     'Replay establishes finite original address/data selection under stated models, not a native power/resource lease.',
                     'RX attachment behavior is not reconstructed; transmit does not call it after attach.',
                     'Original legacy GLINK lookup/attach failures are not a safe API contract; no native call to that wrapper is proposed.'],
          'results': cases}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k not in ['models', 'limits', 'results']}, indent=2))
