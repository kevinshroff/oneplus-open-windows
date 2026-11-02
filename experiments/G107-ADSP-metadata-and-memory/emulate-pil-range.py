"""Exercise installed PIL header/range/segment code using actual phone metadata.

UEFI allocation, physical translation, SCM, file IO, formatting, time and memset
are explicit models. No ADSP instructions or native firmware operation executes.
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
p.add_argument('--adsp', type=Path, required=True)
p.add_argument('--dtb', type=Path, required=True)
p.add_argument('--native-receipt', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
sha = lambda value: hashlib.sha256(value).hexdigest()
raw = a.image.read_bytes()
assert sha(raw) == '75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716'
image = pefile.PE(data=raw).get_memory_mapped_image()
metadata = {'adsp': a.adsp.read_bytes(), 'dtb': a.dtb.read_bytes()}
assert sha(metadata['adsp']) == '353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8'
assert sha(metadata['dtb']) == '5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1'
native = json.loads(json.loads(a.native_receipt.read_text())['output'])
assert native['ok'] and native['FAT_metadata_unchanged'] and native['raw_writes'] == 0
files = {item['Name']: item['Size'] for item in native['ADSP_directory_metadata']}
ARENA, END = 0x30000000, 0x10000000
SAVED = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
         UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
         UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29]


def run(which, *, size=None, override=None, base=None, scm_fail=None,
        bad_magic=False, nonreloc=False, segments=False, short_file=False):
    data = bytearray(metadata[which])
    original_data = bytes(data)
    if bad_magic:
        data[0] ^= 1
    if nonreloc:
        offset = struct.unpack_from('<I', data, 28)[0]
        count = struct.unpack_from('<H', data, 44)[0]
        for i in range(count):
            flags = struct.unpack_from('<I', data, offset+i*32+24)[0]
            struct.pack_into('<I', data, offset+i*32+24, flags & ~0x08000000)
    default_base, default_size, default_override, image_id, name = (
        (0x9ea00000, 0x4880000, 1, 1, 'adsp') if which == 'adsp'
        else (0x9e980000, 0x80000, 0, 36, 'adsp_dtb'))
    base = default_base if base is None else base
    size = default_size if size is None else size
    override = default_override if override is None else override
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, (len(image)+4095) & ~4095)
    u.mem_write(0, image)
    u.mem_map(ARENA, 0x100000)
    u.mem_map(END, 4096)
    ctx, cfg, state, mdt, uncached = [ARENA+v for v in (0x1000, 0x2000, 0x3000, 0x10000, 0x20000)]

    def put(at, fmt, *values):
        u.mem_write(at, struct.pack('<'+fmt, *values))

    put(ctx, 'QQ', cfg, state)
    put(cfg, 'QI', 1, 2)  # Block media, split ELF format.
    u.mem_write(cfg+12, ('FULL_ADSP' if which == 'adsp' else 'FULL_ADSP_DTB').encode('utf-16le')+b'\0\0')
    u.mem_write(cfg+0x9c, bytes.fromhex('a2a0d0ebe5b9334487c068b6b72699c7'))
    u.mem_write(cfg+0xac, ('\\image\\'+name).encode('utf-16le')+b'\0\0')
    put(cfg+0xec, 'IQQ', image_id, base, size)
    u.mem_write(cfg+0x102, bytes([override]))
    u.mem_write(mdt, bytes(data))
    u.mem_write(uncached, bytes(data))
    put(state+0x30, 'QQ', mdt, uncached)
    allocation, events, zeroes, reads = ARENA+0x40000, [], [], []

    def ret(value=0):
        u.reg_write(UC_ARM64_REG_X0, value)
        u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    def wide(pointer):
        b = bytes(u.mem_read(pointer, 128))
        end = next(i for i in range(0, len(b), 2) if b[i:i+2] == b'\0\0')
        return b[:end].decode('utf-16le')

    def hook(uc, pc, amount, unused):
        nonlocal allocation
        if pc == 0x79ec:
            n = uc.reg_read(UC_ARM64_REG_X0)
            assert 0 < n <= 4096 and allocation+n < ARENA+0x80000
            result = allocation
            allocation = (allocation+n+15) & ~15
            uc.mem_write(result, bytes(n))
            ret(result)
        elif pc == 0xfa14:
            ret(0x38000000)  # Modeled physical metadata buffer, never native memory.
        elif pc == 0x248c:
            command = uc.reg_read(UC_ARM64_REG_X1)
            values = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                                  UC_ARM64_REG_X4, UC_ARM64_REG_X5)]
            assert command in (0x2000201, 0x2000202)
            events.append({'call': 'SCM_model', 'command': hex(command),
                           'parameter_id': hex(values[0]), 'image_id': values[1],
                           'address': values[2], 'size_or_unused': values[3]})
            ret(0x8000000000000007 if scm_fail == command else 0)
        elif pc == 0x7c7c:
            raise AssertionError('OEM assertion')
        elif pc in (0x7b80, 0x11cd4):
            ret(0)
        elif pc == 0x4f6c:
            assert wide(uc.reg_read(UC_ARM64_REG_X2)) == '%s.b%02d'
            path = wide(uc.reg_read(UC_ARM64_REG_X3))
            index = uc.reg_read(UC_ARM64_REG_X4)
            text = (path+'.b'+str(index).zfill(2)).encode('utf-16le')+b'\0\0'
            assert len(text) <= 64
            uc.mem_write(uc.reg_read(UC_ARM64_REG_X0), text)
            ret(0)
        elif pc == 0x6cd8:
            path = wide(uc.reg_read(UC_ARM64_REG_X0))
            size_pointer = uc.reg_read(UC_ARM64_REG_X6)
            n = struct.unpack('<Q', uc.mem_read(size_pointer, 8))[0]
            stack = uc.reg_read(UC_ARM64_REG_SP)
            destination, capacity = struct.unpack('<QQ', uc.mem_read(stack, 16))
            filename = path.rsplit('\\', 1)[-1]
            assert filename in files and n == files[filename] and capacity == n
            reads.append({'name': filename, 'address': destination, 'bytes': n})
            if short_file and len(reads) == 1:
                put(size_pointer, 'Q', n-1)
            ret(0)
        elif pc == 0x7e34:
            address, n = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1)]
            if n:
                zeroes.append({'address': address, 'bytes': n})
            ret(address)

    u.hook_add(UC_HOOK_CODE, hook)

    def invoke(entry):
        stack = ARENA+0xfffe0
        u.reg_write(UC_ARM64_REG_SP, stack)
        u.reg_write(UC_ARM64_REG_LR, END)
        u.reg_write(UC_ARM64_REG_X0, ctx)
        for i, reg in enumerate(SAVED):
            u.reg_write(reg, 0x8800000000000000+i*256)
        before = [u.reg_read(reg) for reg in SAVED]
        u.emu_start(entry, END, count=1000000)
        assert u.reg_read(UC_ARM64_REG_PC) == END and u.reg_read(UC_ARM64_REG_SP) == stack
        assert [u.reg_read(reg) for reg in SAVED] == before
        return u.reg_read(UC_ARM64_REG_X0)

    validation = invoke(0x265c)
    outcome, assertion, segment_result = None, None, None
    if validation == 0:
        try:
            outcome = invoke(0x2768)
        except AssertionError as error:
            if str(error) != 'OEM assertion':
                raise
            assertion = str(error)
        if outcome == 0 and segments:
            segment_result = invoke(0x3478)
    selected_base, selected_size, original_base = struct.unpack('<QQQ', u.mem_read(state, 24))
    return {'image': which, 'metadata_sha256': sha(original_data),
            'controlled_metadata_mutation': bad_magic or nonreloc,
            'config_base': base, 'config_size': size, 'override': override,
            'validation_status': validation, 'range_status': outcome, 'assertion': assertion,
            'selected_base': selected_base, 'selected_size': selected_size,
            'original_ELF_base': original_base, 'segment_status': segment_result,
            'SCM_events': events, 'modeled_reads': reads, 'modeled_zeroes': zeroes}


rows = []
for name, which, kwargs, validation, expected in [
    ('actual-adsp', 'adsp', {'segments': True}, 0, 0),
    ('old-reservation-too-small', 'adsp', {'size': 0x4080000}, 0, 4),
    ('no-override-valid', 'adsp', {'override': 0}, 0, 0),
    ('no-override-old-size', 'adsp', {'override': 0, 'size': 0x4080000}, 0, 2),
    ('range-SCM-error', 'adsp', {'scm_fail': 0x2000202}, 0, 7),
    ('metadata-SCM-error', 'adsp', {'scm_fail': 0x2000201}, 7, None),
    ('unaligned-base', 'adsp', {'base': 0x9ea00001}, 0, None),
    ('controlled-nonreloc-header', 'adsp', {'nonreloc': True}, 0, 4),
    ('actual-adsp-dtb', 'dtb', {'segments': True}, 0, 0),
    ('dtb-reservation-too-small', 'dtb', {'size': 0x1000}, 0, 2),
    ('dtb-range-SCM-error', 'dtb', {'scm_fail': 0x2000202}, 0, 7),
    ('controlled-invalid-magic', 'dtb', {'bad_magic': True}, 1, None),
    ('segment-short-read-stops', 'adsp', {'segments': True, 'short_file': True}, 0, 0),
]:
    row = run(which, **kwargs)
    assert row['validation_status'] == validation and row['range_status'] == expected, (name, row)
    if name == 'unaligned-base':
        assert row['assertion'] == 'OEM assertion'
    if kwargs.get('segments'):
        assert row['segment_status'] == (11 if kwargs.get('short_file') else 0), (name, row)
    row['case'] = name
    rows.append(row)
actual = rows[0]
assert actual['selected_base'] == 0x9ea00000 and actual['selected_size'] == 0x4880000
overlap = max(0, min(actual['selected_base']+actual['selected_size'], 0xa5580000)-max(actual['selected_base'], 0xa2a80000))
assert overlap == 8 << 20
assert len(actual['modeled_reads']) == 54
max_write = max(item['address']+item['bytes'] for item in actual['modeled_reads']+actual['modeled_zeroes'])
assert max_write < 0xa2a80000
result = {'passed': True, 'cases': len(rows), 'PILDxe_sha256': sha(raw),
          'original_ARM64_unmodified': True, 'native_operations': 0,
          'actual_ADSP_range_overlaps_compiled_Demura_bytes': overlap,
          'actual_split_loader_max_modeled_write_end': max_write,
          'observations': ['The actual metadata requires72.5MiB; shrinking to64.5MiB is refused.',
                           'The split loader issues54file reads with sizes matching native directory entries.',
                           'Pure BSS segments with zero filesz are skipped by this loader; no direct write into the overlap is observed in the segment-copy model.'],
          'modeled_boundaries': ['UEFI allocation', 'physical metadata translation', 'SCM',
                                'file IO', 'UTF16 formatting', 'time', 'zero-fill writes'],
          'limits': ['SCM success is modeled; authentication, ownership and processor start are not qualified.',
                     'Segment payload bytes are not read or executed in this model.',
                     'The conflicting reservation remains unresolved even though modeled copy writes stop below it.'],
          'results': rows}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key: result[key] for key in ('passed', 'cases', 'native_operations', 'actual_ADSP_range_overlaps_compiled_Demura_bytes')}))
