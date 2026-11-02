"""Check the captured native controller context against every firmware value."""
from pathlib import Path
import hashlib
import json
import re
import struct

W = Path(__file__).resolve().parent
logs = W.parent / 'platform-snapshot/private'
context_log = logs / 'debug-live-20261021T060505Z.txt'
pool_log = logs / 'debug-live-20261021T060643Z.txt'
def section(path, tag):
    text = path.read_text(errors='replace').replace('\r\n', '\n')
    a = text.rindex('\n' + tag + '_BEGIN\n')
    b = text.rindex('\n' + tag + '_END\n')
    assert b > a
    return text[a:b]
text = section(context_log, 'G21_CRASH2')
base = 0xffff9a8495291810
buffer = bytearray(224)
seen = set()
for line in text.splitlines():
    m = re.fullmatch(r'([a-f0-9]{8}`[a-f0-9]{8})\s+([a-f0-9]{8}) ([a-f0-9]{8}) ([a-f0-9]{8}) ([a-f0-9]{8})', line)
    if not m:
        continue
    off = int(m[1].replace('`', ''), 16) - base
    assert off % 16 == 0 and 0 <= off <= len(buffer)-16 and off not in seen
    seen.add(off)
    struct.pack_into('<4I', buffer, off, *[int(x, 16) for x in m.groups()[1:]])
assert seen == set(range(0, len(buffer), 16))
u32 = lambda o: struct.unpack_from('<I', buffer, o)[0]
u64 = lambda o: struct.unpack_from('<Q', buffer, o)[0]
candidate = json.loads((W / 'controller-table-candidate.json').read_text())
for value in candidate['selector4_values']:
    assert u32(int(value['context_offset'], 16)) == value['value'], value
assert u64(0) == 0xf000000 and u32(0x10) == 0x1000000
assert u32(0x14) == 384 and u32(0x18) == 210 and u32(0x20) == 0 and u32(0x24) == 4096
assert u64(8) == 0, 'Release has already unmapped the TLMM region in this capture'
raw_buffer = u64(0x30)
assert raw_buffer == 0xffff9a849521edb0
text = section(pool_log, 'G21_CRASH3')
records = bytearray(96)
record_base = 0xffff9a84952abcd0
seen = set()
for line in text.splitlines():
    m = re.fullmatch(r'([a-f0-9]{8}`[a-f0-9]{8})\s+([a-f0-9]{8}`[a-f0-9]{8}) ([a-f0-9]{8}`[a-f0-9]{8})', line)
    if not m:
        continue
    off = int(m[1].replace('`', ''), 16)-record_base
    assert 0 <= off <= 80 and off % 16 == 0
    seen.add(off)
    struct.pack_into('<2Q', records, off, *[int(x.replace('`', ''), 16) for x in m.groups()[1:]])
assert seen == set(range(0, 96, 16))
routes = []
for i, expected in enumerate([(57, 25, 569, 256), (98, 174, 645, 320)]):
    row = records[i*48:(i+1)*48]
    pin, gpio, gsi = struct.unpack_from('<HHI', row)
    virtual = struct.unpack_from('<H', row, 8)[0]
    assert (pin, gpio, gsi, virtual) == expected
    en, cfg = [struct.unpack_from('<Q', row, o)[0] for o in [0x10, 0x20]]
    assert en & 4095 == (0xb220010 + 4*(pin >> 5)) & 4095
    assert cfg & 4095 == (0xb220110 + 4*pin) & 4095
    routes.append({'PDC': pin, 'TLMM': gpio, 'GSI': gsi, 'virtual_GPIO': virtual,
                   'enable_mapping_page_offset': hex(en & 4095),
                   'config_mapping_page_offset': hex(cfg & 4095),
                   'enabled_raw': row[0x28], 'configured_raw': row[0x29]})
assert '*ffff9a849521ed10 size:  250' in text and '(Allocated) *gpi0' in text
report = {
    'phase': 'native_controller_contract_values_verified_from_crash_capture',
    'native_context_bytes': len(buffer), 'all_38_primary_values_match': True,
    'direct_GPIO_count': u32(0x18), 'total_virtual_capacity': u32(0x14),
    'TLMM_physical_base': hex(u64(0)), 'TLMM_bytes': u32(0x10), 'pin_stride': u32(0x24),
    'capture_point': 'Release callback after TLMM unmap, immediately before its raw-buffer field would be cleared',
    'initial_PnP_started_independently_verified': True,
    'PDC_routes': routes,
    'raw_flag_limit': 'Post-stop configured bytes are 0 and0xe0; do not assume the record flags are normalized booleans. Constructor initialization needs auditing.',
    'free_call_operand': hex(raw_buffer), 'allocated_pool_block': '0xffff9a849521ed10',
    'pool_block_bytes': 0x250, 'operand_offset_inside_allocated_block': 0xa0,
    'allocation_API': 'WdfMemoryCreate, table index192', 'release_API': 'ExFreePoolWithTag',
    'leading_failure_explanation': 'Incorrect direct pool free of a framework-owned buffer; driver correction remains untested.',
    'context_log_sha256': hashlib.sha256(context_log.read_bytes()).hexdigest(),
    'pool_log_sha256': hashlib.sha256(pool_log.read_bytes()).hexdigest(),
    'context_bytes_sha256': hashlib.sha256(buffer).hexdigest(),
    'pin_IO_touch_interrupt_and_wake_qualification': False,
}
(W / 'native-controller-contract-result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ['phase', 'all_38_primary_values_match', 'total_virtual_capacity', 'PDC_routes']}, indent=2))
