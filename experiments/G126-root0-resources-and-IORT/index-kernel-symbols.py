"""Index matching PDB public metadata, checked against PE exports; no code emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import pefile
import re

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
p.add_argument('--pdb', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--pattern', default=r'Iort|Smmup.*(Map|Process|Find|Device|Root|Id)|Iommu.*(Input|IdMapping|DeviceId)')
a = p.parse_args()
assert not a.output.exists()
image = a.kernel.read_bytes()
assert hashlib.sha256(image).hexdigest() == 'db0c8b367c1927eb4d39d922cb54da4621e9b3c241e2655d33c5ecd46719aa13'
pe = pefile.PE(data=image)
b = a.pdb.read_bytes()
assert hashlib.sha256(b).hexdigest() == 'dd5851a09d71616e42dc6815e3340df0ee37f8ade5fe0dbde01a71b3b1bb7cdb', 'PDB identity differs'
assert b[:32] == b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
block, free, count, size, reserved, directory = struct.unpack_from('<6I', b, 32)
assert block in (512, 1024, 2048, 4096) and count * block == len(b)
u32 = lambda data, at: struct.unpack_from('<I', data, at)[0]
u16 = lambda data, at: struct.unpack_from('<H', data, at)[0]
blocks = struct.unpack_from('<' + 'I' * ((size + block - 1) // block), b, directory * block)
d = b''.join(b[i*block:(i+1)*block] for i in blocks)[:size]
n = u32(d, 0)
sizes = struct.unpack_from('<' + 'I' * n, d, 4)
at = 4 + 4*n
streams = []
for length in sizes:
    nb = 0 if length == 0xffffffff else (length + block - 1) // block
    nums = struct.unpack_from('<' + 'I' * nb, d, at)
    at += 4*nb
    assert all(i < count for i in nums)
    streams.append(b''.join(b[i*block:(i+1)*block] for i in nums)[:length] if nb else b'')
assert at == len(d)
rsds = []
for dbg in pe.DIRECTORY_ENTRY_DEBUG:
    if dbg.struct.Type == 2:
        cv = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)
        if cv[:4] == b'RSDS':
            rsds.append(cv)
assert len(rsds) == 1
assert streams[1][12:28] == rsds[0][4:20] and u32(streams[3], 8) == u32(rsds[0], 20), 'PDB GUID or DBI link age differs'
dbi = streams[3]
records = streams[u16(dbi, 20)]
symbols = {}
at = 0
while at < len(records):
    length = u16(records, at)
    assert length >= 2 and at + length + 2 <= len(records)
    kind = u16(records, at+2)
    if kind == 0x110e:  # S_PUB32: flags, section offset, section, NUL name.
        section = u16(records, at+12)
        offset = u32(records, at+8)
        name = records[at+14:at+2+length].split(b'\0', 1)[0].decode('utf8', 'replace')
        if 0 < section <= len(pe.sections):
            rva = pe.sections[section-1].VirtualAddress + offset
            symbols[name] = {'name': name, 'rva': rva, 'public_flags': u32(records, at+4)}
    at += length + 2
assert at == len(records)
checks = []
export_mismatches = []
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name and not exp.forwarder:
        name = exp.name.decode('ascii')
        if name in symbols:
            if symbols[name]['rva'] == exp.address:
                checks.append(name)
            else:
                export_mismatches.append({'name':name,'export_rva':hex(exp.address),'public_rva':hex(symbols[name]['rva'])})
assert len(checks) == 3208 and len(export_mismatches) == 9

pd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
pdata = pe.get_data(pd.VirtualAddress, pd.Size)
assert len(pdata) % 8 == 0
unwind = {}
for at in range(0, len(pdata), 8):
    begin, data = struct.unpack_from('<II', pdata, at)
    flag = data & 3
    if flag in (1, 2):
        length = ((data >> 2) & 0x7ff) * 4
    elif flag == 0:
        length = (u32(pe.get_data(data, 4), 0) & 0x3ffff) * 4
    else:
        continue  # A jump-island link is not a separate function body.
    if length:
        unwind[begin] = {'bytes': length, 'unwind': hex(data), 'provenance': 'Microsoft ARM64 packed/unpacked unwind metadata; may describe a fragment'}

matches = []
for name, sym in symbols.items():
    if re.search(a.pattern,name,re.I):
        rva = sym['rva']
        row = {**sym, 'rva': hex(rva), 'address': hex(pe.OPTIONAL_HEADER.ImageBase+rva)}
        if rva in unwind:
            row['unwind_range'] = unwind[rva]
        matches.append(row)
result = {'kernel_sha256': hashlib.sha256(image).hexdigest(), 'PDB_sha256': hashlib.sha256(b).hexdigest(), 'PDB_RSDS_GUID_and_DBI_age_match': True, 'PDB_info_stream_age': u32(streams[1],8), 'PDB_DBI_age': u32(streams[3],8), 'image_RSDS_age': u32(rsds[0],20), 'public_symbols': len(symbols), 'export_RVA_matches': len(checks), 'export_public_RVA_differences_uninterpreted': export_mismatches, 'image_base': hex(pe.OPTIONAL_HEADER.ImageBase), 'candidate_publics': matches, 'code_behavior_established': False, 'limit': 'Public metadata locates candidates; a public name or unwind fragment does not establish behavior or complete reachable body.'}
a.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
