"""Losslessly decode the observed AeoB/ACPI-argument resource containers.

No instructions in these descriptions are executed. Argument bounds/counts,
exact re-encoding and the original artifact hash are checked independently
of any interpretation of resource command names or platform compatibility.
"""
from pathlib import Path
import argparse, hashlib, json, struct

W = Path(__file__).resolve().parent
SOURCE = W.parent / 'gpio-G23/private/SPI-firmware'
HASHES = {'BSRC_SPI.bin': '4ce2d0fba6560f544198bfb5de4c3c33ae9d8527a66e5468379a161524926443',
          'BSRC_QSPI.bin': 'b06b6f0a26652f1187bc12e347c53e8a51ef25c47b82cd403c9b73f64e48d11a'}

def decode_args(data, depth=0):
    assert depth < 32
    result, position = [], 0
    while position < len(data):
        assert len(data) - position >= 4
        kind, length = struct.unpack_from('<HH', data, position)
        storage = max(4, length)
        assert storage <= len(data) - position - 4
        payload = data[position + 4:position + 4 + length]
        padding = data[position + 4 + length:position + 4 + storage]
        item = {'type': kind, 'length': length, 'padding_hex': padding.hex()}
        if kind == 0:
            assert length in (4, 8), length
            item['integer'] = int.from_bytes(payload, 'little')
        elif kind == 1:
            assert payload.endswith(b'\0') and b'\0' not in payload[:-1]
            item['string'] = payload[:-1].decode('ascii')
        elif kind == 3:
            item['package'] = decode_args(payload, depth + 1)
        else:
            item['data_hex'] = payload.hex()
        result.append(item)
        position += 4 + storage
    assert position == len(data)
    return result

def encode_args(items):
    output = bytearray()
    for item in items:
        if 'integer' in item:
            payload = item['integer'].to_bytes(item['length'], 'little')
        elif 'string' in item:
            payload = item['string'].encode('ascii') + b'\0'
        elif 'package' in item:
            payload = encode_args(item['package'])
        else:
            payload = bytes.fromhex(item['data_hex'])
        assert len(payload) == item['length']
        padding = bytes.fromhex(item['padding_hex'])
        assert len(padding) == max(4, len(payload)) - len(payload)
        output.extend(struct.pack('<HH', item['type'], len(payload)) + payload + padding)
    return bytes(output)

def decode_container(data, expected):
    assert hashlib.sha256(data).hexdigest() == expected
    assert data[:4] == b'AeoB'
    length, count = struct.unpack_from('<II', data, 4)
    assert length == len(data)
    items = decode_args(data[12:])
    assert len(items) == count
    assert data[:12] + encode_args(items) == data
    return {'sha256': expected, 'bytes': len(data), 'argument_count': count,
            'complete_bounds_and_exact_reencoding_passed': True, 'arguments': items}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.input:
        if not args.sha256 or not args.output:
            parser.error('An explicit input requires --sha256 and --output')
        jobs = [(args.input, args.sha256, args.output)]
    else:
        if args.sha256 or args.output:
            parser.error('--sha256/--output require an input')
        jobs = [(SOURCE / name, expected, W / 'private' / (name + '.json'))
                for name, expected in HASHES.items()]
    for source, expected, output in jobs:
        assert not output.exists(), 'Preserve existing decoded evidence: ' + str(output)
        result = decode_container(source.read_bytes(), expected)
        result['file'] = source.name
        if source.name in HASHES:
            assert result['argument_count'] == 24
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(source.name, 'complete', result['bytes'], 'bytes;',
              result['argument_count'], 'top-level arguments; exact re-encoding passed')


if __name__ == '__main__':
    main()
