"""Exercise the actual G80 volume reader against real-image corruptions."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import lzma

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--fd', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
spec = importlib.util.spec_from_file_location('g106_inventory', Path(__file__).with_name('inventory-fd.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
raw = a.fd.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '93fb6c036781ec946aa7a5a91eb21e756dec17ce57447a16b757670a7dda34e1'
valid = module.Inventory()
valid.volume(raw)
assert len(valid.files) == 215 and len(valid.volumes) == 2
assert len(valid.pmic) == 1 and module.sha(valid.pmic[0]) == 'd8ac0324cdcd53a430bc617ab105a47175bbc9eb18387b9d1852c57961162a68'
top = [entry for entry in valid.files if entry['volume'] == 'FD']
first, compact = top[0], next(entry for entry in top if entry['type'] == '0xb')
start = compact['offset']+24
assert raw[start+3] == 2


def fix_header(data, offset):
    data[offset+16] = 0
    data[offset+16] = (-(sum(data[offset:offset+24])-data[offset+17]-data[offset+23])) & 255


def fix_compact(data):
    offset, size = compact['offset'], compact['bytes']
    if data[offset+19] & 0x40:
        data[offset+17] = (-sum(data[offset+24:offset+size])) & 255
    fix_header(data, offset)


rows = [{'name': 'valid_actual_FD_and_PMIC_extraction', 'passed': True}]
for name in ('truncated_volume', 'bad_volume_checksum', 'bad_file_header_checksum',
             'deleted_file_state', 'zero_file_size', 'unknown_guid_encapsulation',
             'guided_offset_inside_header', 'invalid_lzma', 'unsupported_section', 'duplicate_file_GUID'):
    data = bytearray(raw)
    if name == 'truncated_volume':
        data = data[:-1]
    elif name == 'bad_volume_checksum':
        data[8] ^= 1
    elif name == 'bad_file_header_checksum':
        data[first['offset']] ^= 1
    elif name == 'deleted_file_state':
        data[first['offset']+23] = 0xef
    elif name == 'zero_file_size':
        data[first['offset']+20:first['offset']+23] = b'\0\0\0'
        fix_header(data, first['offset'])
    elif name == 'unknown_guid_encapsulation':
        data[start+4] ^= 1
        fix_compact(data)
    elif name == 'guided_offset_inside_header':
        data[start+20:start+22] = (20).to_bytes(2, 'little')
        fix_compact(data)
    elif name == 'invalid_lzma':
        data[start+24] = 255
        fix_compact(data)
    elif name == 'unsupported_section':
        data[start+3] = 0x20
        fix_compact(data)
    elif name == 'duplicate_file_GUID':
        data[compact['offset']:compact['offset']+16] = data[first['offset']:first['offset']+16]
        fix_compact(data)
    caught = None
    try:
        module.Inventory().volume(bytes(data))
    except (AssertionError, lzma.LZMAError, UnicodeDecodeError) as error:
        caught = type(error).__name__
    assert caught is not None, name
    rows.append({'name': name, 'passed': True, 'refusal': caught})
result = {'passed': True, 'cases': len(rows), 'actual_parser_functions': True,
          'actual_FD_fixture_sha256': module.sha(raw), 'native_operations': 0, 'results': rows}
a.output.write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key: result[key] for key in ('passed', 'cases', 'native_operations')}))
