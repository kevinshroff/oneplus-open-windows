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
        bad_magic=False, nonreloc=False, segments=False, short_file=False, scm_fail_status=0x8000000000000007):
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
            ret(scm_fail_status if scm_fail == command else 0)
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


rows=[]
plans=[('original-dtb-config', 'dtb', {}),
 ('G134-dtb-reservation-span','dtb',dict(base=0xa9f80000,size=0x80000,override=1,segments=True)),
 ('candidate-dtb-exact-span','dtb',dict(base=0xa9f80000,size=0x3000,override=1,segments=True)),
 ('override-no-placement-observation','dtb',dict(base=0xa9f80000,size=0x80000,override=0,segments=True)),
 ('candidate-dtb-error-preserved','dtb',dict(base=0xa9f80000,size=0x3000,override=1,scm_fail=0x2000202)),
 ('G136-diagnostic-memory-stop','dtb',dict(base=0xa9f80000,size=0x80000,override=1,scm_fail=0x2000202,scm_fail_status=0x8000000000000015)),
 ('candidate-main-span-unchanged','adsp',dict(base=0xaa000000,size=0x4880000,override=1,segments=True)),
 ('undersized-override-is-not-qualified','dtb',dict(base=0xa9f80000,size=0x2000,override=1,segments=False))]
for name,which,kw in plans:
 r=run(which,**kw);r['case']=name
 assert r['validation_status']==0 and r['assertion']is None,(name,r)
 if name in ['candidate-dtb-error-preserved','G136-diagnostic-memory-stop']:assert r['range_status']==7 and r['segment_status']is None,(name,r)
 elif name=='override-no-placement-observation':assert r['range_status']==2 and r['segment_status']is None and len(r['SCM_events'])==1
 elif name=='undersized-override-is-not-qualified':assert r['range_status']==4 and r['segment_status']is None and len(r['SCM_events'])==1
 else:assert r['range_status']==0,(name,r)
 if kw.get('segments')and name!='override-no-placement-observation':assert r['segment_status']==0,(name,r)
 expected=(0x9e980000,0x80000)if name=='original-dtb-config'else(kw['base'],kw['size'])
 if name!='override-no-placement-observation':assert(r['selected_base'],r['selected_size'])==expected,(name,r,expected)
 if name=='candidate-dtb-exact-span':
  assert r['SCM_events'][1]['address']==0xa9f80000 and r['SCM_events'][1]['size_or_unused']==0x3000
  assert all(0xa9f80000<=x['address']and x['address']+x['bytes']<=0xa9f83000 for x in r['modeled_reads']+r['modeled_zeroes'])
 if name=='undersized-override-is-not-qualified':r['limit']='Original range helper refuses the undersized override before MEM_SETUP; no payload copy is exercised.'
 rows.append(r)
result={'passed':True,'cases':len(rows),'PILDxe_sha256':sha(raw),'original_ARM64_unchanged':True,'native_operations':0,'results':rows,'models':['UEFI allocation','physical metadata translation','SCM success/error returns','file reads with actual lengths but modeled data writes','time','zero fill'],'limits':['A source/argument discrepancy is demonstrated; this does not prove the native secure failure cause or predict acceptance.','DTB reservation remains0x80000; proposed PAS image extent is0x3000. Main span remains0x4880000.','The stock original UEFI configuration also passes0x80000; disagreement with Linux is not proof that the UEFI request size caused the native failure.','Original range helper refuses an undersized override before MEM_SETUP. OverrideNo at the new base is also refused.']}
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k!='results'},indent=2));print(json.dumps([{'case':r['case'],'base':hex(r['selected_base']),'bytes':hex(r['selected_size']),'range_status':hex(r['range_status'])}for r in rows],indent=2))
