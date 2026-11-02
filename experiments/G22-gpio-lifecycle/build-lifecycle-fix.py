#!/usr/bin/env python3
"""Build a hash-bound, unsigned GPIO development image; never edit the input.

Use only in the disposable RAM WinPE with a connected development debugger.
This is not a release-signed driver package. Original catalog metadata does
not authenticate this altered binary. Other device-owned query allocations
retain their original lifetimes and need a separate restart-growth audit.
"""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess
import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SOURCE_SHA = '3e048697237caf5752e7c1ef40015989339bbed0d22717451ae60187f8d50700'
REGIONS = [(0x2a8c, 4), (0x2cac, 0x50), (0x8020, 0x38), (0x10180, 4)]

def text_section(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, strings = struct.unpack_from('<HHH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * stride) for i in range(count)]
    sh = headers[strings]
    names = data[sh[4]:sh[4] + sh[5]]
    text = None
    for h in headers:
        name = names[h[0]:].split(b'\0')[0]
        assert h[1] not in (4, 9) or h[5] == 0, 'unapplied assembler relocation'
        if name == b'.text':
            text = data[h[4]:h[4] + h[5]]
    assert text is not None
    return text

def build(source, output):
    if output.exists() or output.with_suffix('.json').exists():
        raise ValueError('preserve existing output and receipt')
    original = source.read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA:
        raise ValueError('source artifact mismatch')
    pe = pefile.PE(data=original)
    assert pe.FILE_HEADER.Machine == 0xaa64 and pe.OPTIONAL_HEADER.ImageBase == 0x140000000
    assembly = Path(__file__).with_name('gpio-lifecycle-fix.s')
    obj = output.with_suffix('.o')
    if obj.exists():
        raise ValueError('preserve existing assembly output')
    subprocess.run(['/usr/bin/clang', '--target=aarch64-none-elf', '-c', str(assembly), '-o', str(obj)], check=True)
    code = text_section(obj.read_bytes())
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    patched = bytearray(original)
    regions = []
    for rva, length in REGIONS:
        offset = pe.get_offset_from_rva(rva)
        before = bytes(patched[offset:offset + length])
        after = code[rva:rva + length]
        assert len(after) == length
        decoded = list(decoder.disasm(after, pe.OPTIONAL_HEADER.ImageBase + rva))
        assert sum(i.size for i in decoded) == length and not any(i.mnemonic == 'udf' for i in decoded)
        patched[offset:offset + length] = after
        regions.append({'rva': hex(rva), 'offset': offset, 'length': length,
                        'before': before.hex(), 'after': after.hex(),
                        'instructions': [hex(i.address) + ': ' + i.mnemonic + ' ' + i.op_str for i in decoded]})
    # Remove the now-invalid embedded signature rather than presenting it as valid.
    cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    assert cert.VirtualAddress + cert.Size == len(patched)
    assert cert.VirtualAddress >= max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    cert_offset, cert_size = cert.VirtualAddress, cert.Size
    struct.pack_into('<II', patched, cert.get_file_offset(), 0, 0)
    del patched[cert_offset:]
    updated = pefile.PE(data=patched)
    checksum_offset = updated.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    struct.pack_into('<I', patched, checksum_offset, updated.generate_checksum())
    # Code, imports, unwind tables, resources and section layout stay fixed except
    # for the four explicitly named code regions and signature/checksum fields.
    allowed = {x for r in regions for x in range(r['offset'], r['offset'] + r['length'])}
    allowed.update(range(cert.get_file_offset(), cert.get_file_offset() + 8))
    allowed.update(range(checksum_offset, checksum_offset + 4))
    changed = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    assert set(changed) <= allowed
    output.write_bytes(patched)
    receipt = {'schema': 'G22-GPIO-lifecycle-development-v1', 'source_sha256': SOURCE_SHA,
               'output_sha256': hashlib.sha256(patched).hexdigest(), 'output_bytes': len(patched),
               'assembly_sha256': hashlib.sha256(assembly.read_bytes()).hexdigest(),
               'regions': regions, 'changed_retained_bytes': len(changed),
               'removed_signature': {'offset': cert_offset, 'bytes': cert_size},
               'release_signature_valid': False, 'requires_development_debugger': True,
               'imports_and_unwind_tables_unchanged': True,
               'remaining_query_allocations': 'original device-parent ownership; restart growth not yet qualified'}
    output.with_suffix('.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = build(args.source, args.output)
    print(json.dumps(result, indent=2))
