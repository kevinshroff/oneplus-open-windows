"""Exercise installed SimpleFb selection and GOP publication slices, offline only."""
from pathlib import Path
import argparse, hashlib, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
raw = a.image.read_bytes()
identity = hashlib.sha256(raw).hexdigest()
assert identity == '7bc3c9072ff4737d2f8894a368a6593e7f3938602e7d958858e3186217be3678'
image = pefile.PE(data=raw).get_memory_mapped_image()
rows = []
for name in ['original', 'demura_address_only', 'display_address',
             'missing_display_label', 'demura_label_alias', 'empty_table']:
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image) + 4095) & ~4095)
    u.mem_write(0, image)
    arena, end = 0x30000000, 0x10000000
    u.mem_map(arena, 0x10000)
    u.mem_map(end, 0x1000)
    output = arena + 0x1000
    u.reg_write(UC_ARM64_REG_SP, arena + 0xf000)
    u.reg_write(UC_ARM64_REG_LR, end)
    u.reg_write(UC_ARM64_REG_X0, output)
    u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
    if name == 'demura_address_only':
        u.mem_write(0x7298 + 32, struct.pack('<Q', 0xc1000000))
    if name == 'display_address':
        u.mem_write(0x76d0 + 32, struct.pack('<Q', 0xc2000000))
    if name == 'missing_display_label':
        u.mem_write(0x76d0, b'x')
    if name == 'demura_label_alias':
        u.mem_write(0x7298, b'Display Reserved\0' + bytes(15))
    if name == 'empty_table':
        u.mem_write(0x7010 + 40, bytes(8))
    def guard(cpu, pc, n, arg):
        if pc == 0x1784:
            raise AssertionError('Original ASSERT reached')
    u.hook_add(UC_HOOK_CODE, guard)
    u.emu_start(0x2a88, end, count=200000)
    assert u.reg_read(UC_ARM64_REG_PC) == end
    status = u.reg_read(UC_ARM64_REG_X0)
    chosen = struct.unpack('<Q', u.mem_read(output + 32, 8))[0]
    row = {'case': name, 'controlled_data_mutation': name != 'original',
           'status': hex(status), 'selected_base': hex(chosen)}
    if name in ['missing_display_label', 'empty_table']:
        assert status == 0x800000000000000e and chosen == 0
    else:
        expected = {'original': 0xb8000000, 'demura_address_only': 0xb8000000,
                    'display_address': 0xc2000000, 'demura_label_alias': 0xa2a80000}[name]
        assert status == 0 and chosen == expected
        # Original instruction loading the selected descriptor's low32 base.
        u.reg_write(UC_ARM64_REG_SP, output)
        u.emu_start(0x12f4, 0x12fc, count=10)
        assert u.reg_read(UC_ARM64_REG_X19) == expected
        # EFI allocation is not executed. Supply the resulting GOP structs,
        # then execute only the original field-publication instructions.
        mode, info = arena + 0x3000, arena + 0x4000
        u.mem_write(0x7e38, struct.pack('<Q', mode))
        u.mem_write(mode + 8, struct.pack('<Q', info))
        u.reg_write(UC_ARM64_REG_X22, 0x7000)
        u.reg_write(UC_ARM64_REG_X8, mode)
        u.emu_start(0x1374, 0x1400, count=200)
        gop_base, gop_bytes = struct.unpack('<QQ', u.mem_read(mode + 0x18, 16))
        width, height = struct.unpack('<II', u.mem_read(info + 4, 8))
        assert (gop_base, gop_bytes, width, height) == (expected, 2440*2268*4, 2440, 2268)
        row.update(gop_base=hex(gop_base), gop_bytes=gop_bytes, width=width, height=height)
    rows.append(row)
report = {'passed': True, 'cases': len(rows), 'installed_PE_sha256': identity,
          'original_selection_function': '0x2a88', 'original_helpers_executed': True,
          'publication_slices': ['0x12f4..0x12fc', '0x1374..0x1400'],
          'modeled_boundary': 'preallocated GOP mode/info structures', 'native_operations': 0,
          'results': rows,
          'limits': ['No EFI allocation/installation or DPU programming is executed.',
                     'Published GOP base does not establish every active DPU plane or Demura owner.',
                     'The 32-bit base load is observed; this does not qualify arbitrary addresses above 4GiB.']}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'passed': True, 'cases': len(rows), 'native_operations': 0}))
