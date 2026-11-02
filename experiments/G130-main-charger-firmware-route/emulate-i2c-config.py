"""Execute original I2CDxe config/open code with captured FDT and modeled services.

The hardware initializer is a recorded boundary, never an electrical operation.
Synthetic config mutations test rejection; they do not authorize adding a bus.
"""
from pathlib import Path
import argparse, copy, hashlib, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm64_const import *

from fdtree import Fdt

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--image', required=True, type=Path)
ap.add_argument('--boot-fdt', required=True, type=Path)
ap.add_argument('--output', required=True, type=Path)
a = ap.parse_args()
assert not a.output.exists()
raw = a.image.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'b3aa69541e526a1f53c88c958cc23fe4149d0db648835e35b85b1ce3fdaf1cda'
fdt_hash = hashlib.sha256(a.boot_fdt.read_bytes()).hexdigest()
assert fdt_hash == 'f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29'
fdt = Fdt.read(a.boot_fdt)
image = pefile.PE(data=raw).get_memory_mapped_image()
ARENA, END = 0x30000000, 0x10000000
registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
             UC_ARM64_REG_X3, UC_ARM64_REG_X4]
rows = []


def run(core, mutation=None, open_api=False, null_output=False, property_error=None):
    nodes = copy.deepcopy(fdt.nodes)
    if mutation:
        node, key, value = mutation
        if value is None:
            del nodes[node][key]
        else:
            nodes[node][key] = value
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image) + 4095) & ~4095)
    u.mem_write(0, image)
    u.mem_map(ARENA, 0x100000)
    u.mem_map(END, 4096)
    u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
    stack = ARENA + 0xfff00
    u.reg_write(UC_ARM64_REG_SP, stack)
    u.reg_write(UC_ARM64_REG_LR, END)
    heap = ARENA + 0x10000
    objects, events, handles = {}, [], {}
    output = ARENA + 0x1000
    u.mem_write(output, struct.pack('<Q', 0xcccccccccccccccc))

    def string(at):
        b = bytearray()
        for i in range(256):
            c = u.mem_read(at + i, 1)[0]
            if not c:
                return b.decode('ascii')
            b.append(c)
        raise AssertionError('bounded string')

    def q(at):
        return struct.unpack('<Q', u.mem_read(at, 8))[0]

    def putq(at, value):
        u.mem_write(at, struct.pack('<Q', value))

    def allocate(size):
        nonlocal heap
        assert 0 < size < 4096
        p = heap
        heap += (size + 15) & ~15
        assert heap < ARENA + 0x80000
        objects[p] = size
        events.append({'allocate': size})
        return p

    def ret(value=0):
        u.reg_write(UC_ARM64_REG_X0, value)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def resolve(path):
        # Model the unit-address-insensitive configuration service. Exact raw
        # node names and property bytes remain from the captured boot FDT.
        hits = [n for n in nodes if '/'.join(c.split('@')[0] for c in n.split('/')) == path]
        assert len(hits) <= 1
        return hits[0] if hits else None

    def hook(cpu, pc, size, user):
        z = [u.reg_read(r) for r in registers]
        if pc == 0x72a8:
            path = string(z[2]); node = resolve(path)
            events.append({'config_lookup': path, 'found': node})
            if node is not None:
                handle = list(nodes).index(node) + 1
                handles[handle] = node
                putq(z[0], handle)
            ret(0 if node is not None else 1)
        elif pc == 0x61e8:
            assert string(z[2]) == '%s%d' and z[1] == 100
            text = (string(z[3]) + str(z[4])).encode() + b'\0'
            assert len(text) <= z[1]
            u.mem_write(z[0], text)
            ret(len(text) - 1)
        elif pc in [0x72b0, 0x72b4, 0x72b8, 0x72bc]:
            node, key = handles[q(z[0])], string(z[1])
            b = nodes[node].get(key)
            events.append({'property': key, 'reader': hex(pc), 'found': b is not None})
            if b is None or key == property_error:
                ret(1); return
            if pc == 0x72bc:
                assert len(b) == 1
                u.mem_write(z[2], b)
            elif pc == 0x72b8:
                # Some captured scalar properties (core_irq/min_dma) contain
                # one byte even at this UInt32 call boundary. Zero extension
                # is an explicit property-service model, not native API proof.
                assert len(b) in (1, 4), (key, len(b))
                u.mem_write(z[2], struct.pack('<I', int.from_bytes(b, 'big')))
            elif pc == 0x72b0:
                u.mem_write(z[2], struct.pack('<I', len(b)))
            else:
                assert len(b) == z[3]
                u.mem_write(z[2], b)
            ret()
        elif pc == 0x42f0:
            ret(allocate(z[0]))
        elif pc == 0x431c:
            ret(allocate(z[1]))
        elif pc == 0x343c:
            assert z[0] in objects
            events.append({'config_cleanup_boundary': True})
            ret()
        elif pc in [0x4444, 0x4448, 0x444c]:
            events.append({'lock_or_mode_boundary': hex(pc)})
            ret()
        elif pc == 0x26cc:
            config = z[1]
            events.append({'hardware_initializer_modeled_not_executed': True,
                           'selected_base': hex(q(config) + struct.unpack('<I', u.mem_read(config + 0x10, 4))[0])})
            putq(z[0], config)
            ret()

    def invalid(cpu, access, at, size, value, user):
        raise AssertionError(('Unexpected/unmodeled memory access', hex(at), access))

    u.hook_add(UC_HOOK_CODE, hook)
    u.hook_add(UC_HOOK_MEM_INVALID, invalid)
    u.reg_write(UC_ARM64_REG_X0, core)
    u.reg_write(UC_ARM64_REG_X1, 0 if null_output else output)
    u.emu_start(0x2878 if open_api else 0x3064, END, count=200000)
    assert u.reg_read(UC_ARM64_REG_PC) == END and u.reg_read(UC_ARM64_REG_SP) == stack
    result = u.reg_read(UC_ARM64_REG_X0)
    init = [v for v in events if 'hardware_initializer_modeled_not_executed' in v]
    config = q(q(q(output))) if open_api and result == 0 else result if not open_api else 0
    selected = None
    if config:
        selected = {'base': hex(q(config)), 'offset': hex(struct.unpack('<I', u.mem_read(config + 0x10, 4))[0]),
                    'effective_base': hex(q(config) + struct.unpack('<I', u.mem_read(config + 0x10, 4))[0]),
                    'hub': u.mem_read(config + 0x1d, 1)[0],
                    'clock': string(q(q(config + 0x48)))}
    row = {'core': core, 'entry': 'open2878' if open_api else 'config3064', 'null_output': null_output,
           'mutation': None if mutation is None else [mutation[0], mutation[1], None if mutation[2] is None else mutation[2].hex()],
           'property_error': property_error, 'return_code' if open_api else 'config_present': result if open_api else bool(result),
           'selected': selected, 'hardware_initializer_boundary_calls': len(init), 'events': events}
    rows.append(row)
    return row


for core, base in [(1, '0x980000'), (3, '0x988000'), (4, '0x98c000'), (19, '0x880000'), (23, '0x890000')]:
    r = run(core); assert r['config_present'] and r['selected']['effective_base'] == base
    r = run(core, open_api=True); assert r['return_code'] == 0 and r['hardware_initializer_boundary_calls'] == 1
for core in [0, 2, 5, 6, 7, 24]:
    r = run(core); assert not r['config_present'] and not r['hardware_initializer_boundary_calls']
    r = run(core, open_api=True); assert r['return_code'] == 0x1c and not r['hardware_initializer_boundary_calls']
    assert not any('allocate' in e or 'property' in e for e in r['events'])
r = run(6, open_api=True, null_output=True); assert r['return_code'] == 1
node = '/soc/i2c@900000/i2c_device_config_1@1'
for key, value in [('qupv3_instance', b'\x03'), ('core_base_addr', struct.pack('>I', 0xa00000)),
                   ('common_base_addr', struct.pack('>I', 0xac0000)), ('core_offset', struct.pack('>I', 0x100004)),
                   ('tcsr_base_addr', struct.pack('>I', 0xb000000)), ('tcsr_reg_offset', struct.pack('>I', 0x30004))]:
    r = run(1, mutation=(node, key, value), open_api=True)
    assert r['return_code'] == 0x1c and not r['hardware_initializer_boundary_calls']
for key in ['i2c_hub', 'se_clock', 'scl_encoding']:
    r = run(1, property_error=key, open_api=True)
    assert r['return_code'] == 0x1c and not r['hardware_initializer_boundary_calls']

report = {'passed': True, 'cases': len(rows), 'original_config_and_open_instructions_executed': True,
          'I2CDxe_sha256': hashlib.sha256(raw).hexdigest(), 'captured_boot_fdt_sha256': fdt_hash,
          'native_operations': 0, 'main994000_configured_in_captured_FDT': False,
          'limits': ['FDT/property, formatting, allocation/free, locking and hardware initialization are explicit service models.',
                    'UInt32 service calls zero-extend captured one-byte scalars in the model; native DTBExtn conversion is not qualified here.',
                    'Missing-core6 refusal occurs before any property getter/allocation/hardware boundary, independent of modeled scalar conversion.',
                    'The original config builder, range checks, clock-list/timing construction and open control flow execute.',
                    'Successful modeled open does not prove electrical operation or native cleanup.',
                    'Captured historical boot data does not independently prove current live protocol/config state.',
                    'No main-bus node is added and no clock, pin, rail, reset, DSP or charging operation is performed.'],
          'results': rows}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ['passed', 'cases', 'native_operations', 'main994000_configured_in_captured_FDT']}))
