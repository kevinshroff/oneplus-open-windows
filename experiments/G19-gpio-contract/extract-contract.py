"""Extract the observed layout from the exact GPIO binary; never configure hardware."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid

binary = Path(sys.argv[1])
oracle = json.loads(Path(sys.argv[2]).read_text()) if len(sys.argv) > 2 else None
b = binary.read_bytes()
digest = hashlib.sha256(b).hexdigest()
assert digest == '3e048697237caf5752e7c1ef40015989339bbed0d22717451ae60187f8d50700'
u16 = lambda o: struct.unpack_from('<H', b, o)[0]
u32 = lambda o: struct.unpack_from('<I', b, o)[0]
assert b[:2] == b'MZ'
pe = u32(0x3c)
assert b[pe:pe+4] == b'PE\0\0' and u16(pe+4) == 0xaa64
optional = pe + 24
assert u16(optional) == 0x20b
base = struct.unpack_from('<Q', b, optional+24)[0]
sections = []
for i in range(u16(pe+6)):
    p = optional + u16(pe+20) + 40*i
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', b, p+8)
    sections.append((rva, raw_size, raw_offset))

def read(va, n):
    rva = va-base
    found = [(start, offset) for start, size, offset in sections
             if 0 <= rva-start and n <= size-(rva-start)]
    assert len(found) == 1
    start, offset = found[0]
    data = b[offset+rva-start:offset+rva-start+n]
    assert len(data) == n
    return data

checks = {}
if oracle:
    for name in ['g19GpioRead0', 'g19GpioRead1', 'g19GpioOffsetTable0',
                 'g19GpioOffsetTable1', 'g19GpioHelperBytes']:
        record = oracle[name]
        assert record['subject']['digest']['sha256'] == digest
        n = record['normalized_result']
        assert n['complete'] and n['returned_bytes'] == n['requested_bytes']
        assert read(int(n['address'], 16), n['requested_bytes']).hex() == n['bytes_hex']
        checks[name] = {'evidence_id': record['evidence_id'], 'all_bytes_match': True}

tables = {}
for variant, count, address in [(0, 38, 0x14000c310), (1, 42, 0x14000c260)]:
    raw = read(address, count*4)
    values = struct.unpack('<'+'I'*count, raw)
    assert len(set(values)) == count and all(v % 4 == 0 for v in values)
    tables[str(variant)] = {
        'selector1_raw_value': variant, 'required_selector4_argument_count': count,
        'table_VA': hex(address), 'table_sha256': hashlib.sha256(raw).hexdigest(),
        'argument_to_context_offset': [
            {'argument': i, 'offset': hex(0x38+v)} for i, v in enumerate(values)],
    }

r = {
    'artifact_sha256': digest, 'architecture': 'ARM64', 'image_base': hex(base),
    'query_helper_VA': '0x1400031b0', 'prepare_VA': '0x140001190',
    'method': read(0x140002c14, 4).decode('ascii'),
    'UUID': str(uuid.UUID(bytes_le=read(0x14000c250, 16))),
    'IOCTL_raw': hex(struct.unpack('<I', read(0x140003340, 4))[0]),
    'indirect_WDF_table_offset': '0x5d0', 'WDF_function_index': 186,
    'WDF_candidate': 'WdfIoTargetSendIoctlSynchronously; primary KMDF enum/prototype cross-check',
    'input_layout_from_ARM64': {
        'signature': 'AeiC', 'bytes_without_fourth_argument_elements': 56,
        'argument_count': 4,
        'arguments': [
            {'index': 0, 'offset': 16, 'type_raw': 2, 'data_bytes': 16, 'value': 'UUID above'},
            {'index': 1, 'offset': 36, 'type_raw': 0, 'data_bytes': 4, 'value': 0},
            {'index': 2, 'offset': 44, 'type_raw': 0, 'data_bytes': 4, 'value': 'selector 1,2,3,4'},
            {'index': 3, 'offset': 52, 'type_raw': 4, 'data_bytes': '8*(context+0x1c & 0x1fff); zero in observed preparation'},
        ],
        'type4_semantics': 'raw type retained; no undocumented package encoding assumed',
    },
    'scalar_return_storage_from_ARM64': {'1': 'context+0x20', '2': 'context+0x18', '3': 'context+0x24'},
    'selector4_layout_variants': tables,
    'helper_status_failure_path': {
        'status_test': 'nonzero w0 after indirect WDF call branches to bugcheck path',
        'call_VA': '0x1400032f0', 'KeBugCheckEx_arguments': ['0x14e', '0', '0', '0', '0'],
        'limit': 'validated instruction path; not triggered on the phone',
    },
    'independent_REA_initialized_byte_checks': checks,
    'limits': [
        'This describes compiled layout, not a complete working firmware contract.',
        'Selector1 layout variant is not the silicon revision.',
        'Selector2/3 meanings and hardware register values are not supplied.',
        'No ACPI/device installation, GPIO write or physical controller test.',
        'Caller contains resize branches; helper failure behavior means no runtime resize guarantee.',
    ],
}
assert r['method'] == '_DSM' and r['IOCTL_raw'] == '0x32c004'
print(json.dumps(r, indent=2))
