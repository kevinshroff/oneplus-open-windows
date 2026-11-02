"""Rebuild the exact shim and run its unchanged instructions in RAM-only models."""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--shim', required=True, type=Path)
p.add_argument('--source', required=True, type=Path)
p.add_argument('--fd', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
assert not a.output.exists()
a.output.mkdir()
sha = lambda b: hashlib.sha256(b).hexdigest()
shim, fd = a.shim.read_bytes(), a.fd.read_bytes()
assert len(shim) == 112 and sha(shim) == '1f5950ef61a07aeff91a6435821d54c72942d1d85757a5dfaa50f01513c26115'
assert len(fd) == 0x400000 and sha(fd) == 'fc9356a77480491d34496509ef1b8dd8c5f37d012f86e704a42767149aa2319c'
dest, count = struct.unpack_from('<QQ', shim, 8)
assert (dest, count) == (0xc7cc0000, len(fd))
obj = a.output / 'BootShim.o'
cmd = ['clang', '--target=aarch64-linux-gnu', '-c', str(a.source), '-o', str(obj),
       '-DUEFI_BASE=0xC7CC0000', '-DUEFI_SIZE=0x400000']
r = subprocess.run(cmd, capture_output=True, text=True)
(a.output / 'compiler.txt').write_text(r.stdout + r.stderr)
assert r.returncode == 0, r.stderr
# ELF64 relocatable object; .text contains the exact standalone binary here.
data = obj.read_bytes()
assert data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 183
off = struct.unpack_from('<Q', data, 40)[0]
stride, number, names = struct.unpack_from('<HHH', data, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, off+i*stride) for i in range(number)]
strhdr = sections[names]
strings = data[strhdr[4]:strhdr[4]+strhdr[5]]
text = [s for s in sections if strings[s[0]:].split(b'\0', 1)[0] == b'.text']
assert len(text) == 1 and data[text[0][4]:text[0][4]+text[0][5]] == shim
rows = []
for start in [0xa8000000, 0xa9ffff90, dest-len(shim)]:
    source = start+len(shim)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ranges = sorted([(start&~4095, (source+len(fd)+4095)&~4095),
                     (dest&~4095, (dest+len(fd)+4095)&~4095)])
    merged = []
    for lo, hi in ranges:
        if merged and lo <= merged[-1][1]: merged[-1][1] = max(hi, merged[-1][1])
        else: merged.append([lo, hi])
    for lo, hi in merged: u.mem_map(lo, hi-lo)
    u.mem_write(start, shim+fd)
    initial_sp, initial_x0 = 0x12345000, 0x81a04000
    u.reg_write(UC_ARM64_REG_SP, initial_sp)
    u.reg_write(UC_ARM64_REG_X0, initial_x0)
    writes = {'bytes': 0, 'events': 0, 'first': None, 'end': None}
    reached = [False]

    def write(cpu, access, at, size, value, user):
        assert dest <= at and at+size <= dest+len(fd)
        writes['bytes'] += size; writes['events'] += 1
        writes['first'] = at if writes['first'] is None else min(writes['first'], at)
        writes['end'] = at+size if writes['end'] is None else max(writes['end'], at+size)

    def code(cpu, pc, size, user):
        if pc == dest:
            reached[0] = True
            u.emu_stop()

    u.hook_add(UC_HOOK_MEM_WRITE, write)
    u.hook_add(UC_HOOK_CODE, code)
    u.emu_start(start, dest+4, count=2000000)
    assert reached[0] and u.reg_read(UC_ARM64_REG_PC) == dest
    assert sha(bytes(u.mem_read(dest, len(fd)))) == sha(fd)
    assert u.reg_read(UC_ARM64_REG_SP) == initial_sp and u.reg_read(UC_ARM64_REG_X0) == initial_x0
    assert writes['bytes'] == (0 if source == dest else len(fd))
    if source != dest: assert writes['first'] == dest and writes['end'] == dest+len(fd)
    rows.append({'modeled_entry': hex(start), 'modeled_payload_source': hex(source),
                 'destination': hex(dest), 'payload_bytes': len(fd), 'writes': writes,
                 'SP_and_X0_preserved': True, 'destination_digest_matches': True})
report = {'passed': True, 'cases': len(rows), 'compiled_source_matches_112_shim_bytes': True,
          'shim_sha256': sha(shim), 'source_sha256': sha(a.source.read_bytes()), 'FD_sha256': sha(fd),
          'native_operations': 0,
          'limits': ['Entry/source addresses are controlled hypotheses, not a native bootloader-location measurement.',
                    'Execution stops at the destination entry; the firmware body does not execute in this model.',
                    'RAM/cache/MMU/environment are models. No electrical device or hardware cache operation occurs.',
                    'This proves the shim copy footprint, not global DMA ownership or PAS acceptance of new memory.'],
          'results': rows}
(a.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({k: report[k] for k in ['passed', 'cases', 'compiled_source_matches_112_shim_bytes', 'native_operations']}))
