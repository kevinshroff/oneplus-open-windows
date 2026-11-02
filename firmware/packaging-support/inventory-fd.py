"""Inventory the retained hash-bound G80 FD and its LZMA-contained PI volumes.

No firmware executes. Bounds, PI header/file checksums and every retained FFS
    membership/digests are compared. Unsupported encapsulation stops the inventory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import lzma
import struct
import uuid

CONFIGS = {'dde58710-41cd-4306-dbfb-3fa90bb1d2dd': 'uefiplat.cfg',
           '21e9bdd9-6c3f-4f10-84a5-bbec322741f1': 'uefipil.cfg',
           '45fe4b7c-150c-45da-a021-4beb2048ec6f': 'QcomChargerCfg.cfg'}

def sha(data):
    return hashlib.sha256(data).hexdigest()


def guid(data):
    return str(uuid.UUID(bytes_le=data))


def aligned(value, alignment):
    return (value+alignment-1) & ~(alignment-1)


class Inventory:
    def __init__(self):
        self.files = []
        self.volumes = []
        self.encapsulations = []
        self.pmic = []
        self.configs = {}

    def sections(self, data, owner, path, depth):
        assert depth < 8
        offset = 0
        while offset < len(data):
            assert len(data)-offset >= 4
            size = int.from_bytes(data[offset:offset+3], 'little')
            kind = data[offset+3]
            header = 4
            if size == 0xffffff:
                assert len(data)-offset >= 8
                size = int.from_bytes(data[offset+4:offset+8], 'little')
                header = 8
            assert header <= size <= len(data)-offset, (path, offset, size)
            part = data[offset:offset+size]
            body = part[header:]
            label = path+'/'+hex(offset)
            owner['section_types'].append(hex(kind))
            if kind == 0x02:
                assert len(body) >= 20
                algorithm = guid(body[:16])
                start, attrs = struct.unpack_from('<HH', body, 16)
                assert header+20 <= start <= size
                assert algorithm == 'ee4e5898-3914-4259-9d6e-dc7bd79403cf', algorithm
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
                expanded = decoder.decompress(part[start:], max_length=32 << 20)
                assert decoder.eof and not decoder.unused_data and len(expanded) < 32 << 20
                self.encapsulations.append({'path': label, 'algorithm': algorithm,
                                            'attributes': attrs, 'data_offset': start,
                                            'compressed_bytes': size-start,
                                            'expanded_bytes': len(expanded), 'expanded_sha256': sha(expanded)})
                self.sections(expanded, owner, label+'/LZMA', depth+1)
            elif kind == 0x17:
                self.volume(body, label+'/FV', depth+1)
            elif kind == 0x15:
                assert len(body) % 2 == 0
                owner['ui_names'].append(body.decode('utf-16le').rstrip('\0'))
            elif kind == 0x10 and owner['guid'] == '5776232e-082d-4b75-9a0e-fe1d13f7a5d9':
                assert body[:2] == b'MZ'
                self.pmic.append(body)
            elif kind == 0x19 and owner['guid'] in CONFIGS:
                name = CONFIGS[owner['guid']]
                assert name not in self.configs
                self.configs[name] = body
            elif kind in (0x10, 0x12, 0x13, 0x14, 0x18, 0x19, 0x1b, 0x1c):
                pass  # Standard leaf sections; no nested firmware-volume interpretation.
            else:
                raise AssertionError(('Unsupported section', path, hex(kind)))
            new = aligned(offset+size, 4)
            assert not any(data[offset+size:min(new, len(data))])
            offset = min(new, len(data))

    def volume(self, data, path='FD', depth=0):
        assert depth < 8 and 72 <= len(data) <= 32 << 20
        assert data[40:44] == b'_FVH' and data[55] == 2
        assert guid(data[16:32]) in ('8c8ce578-8a3d-4f1c-9935-896185c32dd3',
                                      '5473c07a-3dcb-4dca-bd6f-1e9689e7349a')
        length = struct.unpack_from('<Q', data, 32)[0]
        header = struct.unpack_from('<H', data, 48)[0]
        assert length == len(data) and 72 <= header <= length and header % 2 == 0
        assert sum(struct.unpack('<'+'H'*(header//2), data[:header])) & 0xffff == 0
        erase = 0xff if struct.unpack_from('<I', data, 44)[0] & 0x800 else 0
        self.volumes.append({'path': path, 'bytes': length, 'header_bytes': header, 'sha256': sha(data)})
        offset = aligned(header, 8)
        names = set()
        while offset < length:
            if all(value == erase for value in data[offset:]):
                break
            assert len(data)-offset >= 24
            block = data[offset:offset+24]
            name, kind, attrs = guid(block[:16]), block[18], block[19]
            size = int.from_bytes(block[20:23], 'little')
            hsize = 24
            if attrs & 1:
                assert size == 0 and len(data)-offset >= 32
                size = struct.unpack_from('<Q', data, offset+24)[0]
                hsize = 32
            assert hsize <= size <= length-offset
            raw = data[offset:offset+size]
            assert (sum(raw[:hsize])-raw[17]-raw[23]) & 255 == 0, ('File header checksum', name)
            state = raw[23] ^ erase
            assert state.bit_length() > 0 and 1 << (state.bit_length()-1) == 4, ('File state', name, state)
            body = raw[hsize:]
            if attrs & 0x40:
                assert (sum(body)+raw[17]) & 255 == 0, ('File data checksum', name)
            else:
                assert raw[17] == 0xaa
            normalized = bytearray(raw)
            normalized[23] = 7  # GenFfs input state before GenFv erase-polarity inversion.
            item = {'guid': name, 'type': hex(kind), 'offset': offset, 'bytes': size,
                    'sha256': sha(raw), 'state7_sha256': sha(normalized), 'stored_state': raw[23],
                    'volume': path, 'ui_names': [], 'section_types': []}
            if kind != 0xf0:
                assert name not in names
                names.add(name)
                self.files.append(item)
                if kind != 1:
                    self.sections(body, item, path+'/'+name, depth)
            offset = aligned(offset+size, 8)
        assert len(self.files) < 512


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fd', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pmic-output', type=Path)
    parser.add_argument('--configs-output', type=Path)
    args = parser.parse_args()
    assert not args.output.exists()
    assert args.pmic_output is None or not args.pmic_output.exists()
    assert args.configs_output is None or not args.configs_output.exists()
    raw = args.fd.read_bytes()
    assert sha(raw) == '93fb6c036781ec946aa7a5a91eb21e756dec17ce57447a16b757670a7dda34e1'
    inv = Inventory()
    inv.volume(raw)
    expected = json.loads(args.manifest.read_text())
    actual = {row['guid']: row for row in inv.files}
    assert len(actual) == len(inv.files)
    comparison = {'exact_matches': [], 'state7_matches': [], 'unmatched_included': [],
                  'generated_but_not_included': [], 'included_without_generated_manifest': []}
    expected_by_guid = {}
    for name, digest in expected.items():
        key = name.rsplit('/', 1)[-1].removesuffix('.ffs').lower()
        assert key not in expected_by_guid
        expected_by_guid[key] = digest
        if key not in actual:
            comparison['generated_but_not_included'].append(name)
        elif actual[key]['sha256'] == digest:
            comparison['exact_matches'].append(key)
        elif actual[key]['state7_sha256'] == digest:
            comparison['state7_matches'].append(key)
        else:
            comparison['unmatched_included'].append(name)
    comparison['included_without_generated_manifest'] = sorted(set(actual)-set(expected_by_guid))
    assert len(inv.pmic) == 1
    if args.pmic_output is not None:
        args.pmic_output.write_bytes(inv.pmic[0])
    assert set(inv.configs) == set(CONFIGS.values())
    for key, name in CONFIGS.items():
        assert name in actual[key]['ui_names']
    if args.configs_output is not None:
        args.configs_output.mkdir()
        for name, data in inv.configs.items():
            (args.configs_output/name).write_bytes(data)
    missing = ['4bce7f36-428e-4393-99e3-7e0844404dba', '2e3042f3-2bb9-463f-8866-56d75b7c4ab0',
               'eee9c2b1-16ca-4f34-87ea-2e6d1e160cc4']
    assert all(value not in actual for value in missing)
    result = {'passed': True, 'FD_sha256': sha(raw), 'files': inv.files, 'volumes': inv.volumes,
              'encapsulations': inv.encapsulations, 'generated_manifest_comparison': comparison,
              'all_included_generated_files_match_exactly_or_state7': not comparison['unmatched_included'],
              'missing_charger_GUIDs': missing, 'PmicDxe_PE_sha256': sha(inv.pmic[0]),
              'raw_configs': {name: {'bytes': len(value), 'sha256': sha(value)} for name, value in inv.configs.items()},
              'native_operations': 0,
              'limits': ['Hash-bound G80 format reader; unsupported encapsulations fail explicitly.',
                         'The generated FFS directory is not an authoritative dispatch inventory. Differences are reported rather than waived.',
                         'Parsing establishes file membership/bytes, not successful native initialization.']}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    summary = {k: result[k] for k in ('passed', 'all_included_generated_files_match_exactly_or_state7', 'PmicDxe_PE_sha256')}
    summary.update(file_count=len(inv.files), volume_count=len(inv.volumes))
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
