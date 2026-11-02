"""Inspect a frozen G107 raw-read result and installed-reference data offline."""
from pathlib import Path
import argparse
import base64
import configparser
import hashlib
import json
import re
import shutil
import struct
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--native-receipt', type=Path, required=True)
p.add_argument('--prepi', type=Path, required=True)
p.add_argument('--pil-config', type=Path, required=True)
p.add_argument('--map-source', type=Path, required=True)
p.add_argument('--build-manifest', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
sha = lambda value: hashlib.sha256(value).hexdigest()
receipt = json.loads(a.native_receipt.read_text())
native = json.loads(receipt['output'])
assert receipt['status'] == 'ok' and native['ok'] and native['raw_writes'] == 0
assert native['FAT_metadata_unchanged'] and native['VFAT_long_names_validated']
allowed = {'adsp.mdt', 'adsp_dtb.mdt', 'adsp_dtb.b01', 'verinfo/ver_info.txt'}
assert set(native['fixed_metadata_files']) == allowed
data = {}
for name, row in native['fixed_metadata_files'].items():
    value = base64.b64decode(row['data_base64'], validate=True)
    assert len(value) == row['bytes'] and sha(value) == row['sha256']
    data[name] = value
directory = {row['Name']: row for row in native['ADSP_directory_metadata']}
images = []
for name in ('adsp.mdt', 'adsp_dtb.mdt'):
    value = data[name]
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', value)
    assert h[0][:7] == b'\x7fELF\x01\x01\x01'
    offset, entry_bytes, count = h[5], h[9], h[10]
    assert entry_bytes == 32 and count and offset+count*32 <= len(value)
    segments = []
    for index in range(count):
        row = dict(zip(('type', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'flags', 'align'),
                       struct.unpack_from('<8I', value, offset+index*32)))
        row.update(index=index, hash_segment=(row['flags'] & 0x07000000) == 0x02000000,
                   relocatable=bool(row['flags'] & 0x08000000))
        row['loadable'] = row['type'] == 1 and not row['hash_segment'] and row['memsz'] != 0
        row['split_file'] = name[:-4]+'.b'+str(index).zfill(2)
        row['split_file_bytes'] = directory.get(row['split_file'], {}).get('Size')
        if row['loadable']:
            assert row['memsz'] >= row['filesz'] and row['paddr']+row['memsz'] <= 0xffffffff
            if row['filesz']:
                assert row['filesz'] == row['split_file_bytes']
        segments.append(row)
    load = [row for row in segments if row['loadable']]
    low = min(row['paddr'] for row in load) & ~4095
    high = (max(row['paddr']+row['memsz'] for row in load)+4095) & ~4095
    images.append({'name': name, 'sha256': sha(value), 'ELF_machine': h[2],
                   'program_headers': count, 'load_min': low, 'load_end': high,
                   'load_span': high-low, 'segments': segments})
te = a.prepi.read_bytes()
assert sha(te) == '9207af80d4f4584d186c9f2f474669ff65b893c5d644f9dce7cbbdb4272a7a02'
source = a.map_source.read_bytes()
map_key = 'Platforms/KailuaPkg/Device/oneplus-open/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c'
expected_source_hash = json.loads(a.build_manifest.read_text())[map_key]
assert expected_source_hash == 'c7ec67769fbcd64cdd709f87128217cbd10c596b8f9aec25268ee40d78a26e2d'
config_bytes = a.pil_config.read_bytes()
assert sha(config_bytes) == '13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387'
config = configparser.ConfigParser(allow_no_value=True, interpolation=None)
config.read_string(config_bytes.decode())
configured_images = {}
for name in ('FULL_ADSP', 'FULL_ADSP_DTB'):
    row = config[name]
    configured_images[name] = {
        'base': int(row['ResvMemoryStart'], 0), 'size': int(row['ResvMemorySize'], 0),
        'type': row['Type'], 'override': row['OverrideElfAddr'], 'image_path': row['ImagePath'],
        'subsystem_id': int(row['SubsysID'], 0),
    }
assert configured_images['FULL_ADSP']['base'] == images[0]['load_min']
assert configured_images['FULL_ADSP']['size'] == images[0]['load_span']
compiled = []
for name in ('PIL Reserved', 'Display Demura'):
    needle = name.encode()+b'\0'
    at = te.find(needle)
    assert at >= 0 and te.find(needle, at+1) < 0 and not any(te[at+len(needle):at+32])
    address, length = struct.unpack_from('<QQ', te, at+32)
    match = re.search(rb'\{\s*"'+name.encode()+rb'"\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)', source)
    assert match and (address, length) == tuple(int(v, 16) for v in match.groups())
    compiled.append({'name': name, 'TE_file_offset': at, 'address': address, 'length': length,
                     'end': address+length})
assert compiled[1]['TE_file_offset']-compiled[0]['TE_file_offset'] == 72
demura = compiled[1]
overlap = max(0, min(images[0]['load_end'], demura['end'])-max(images[0]['load_min'], demura['address']))
assert images[0]['load_span'] == 0x4880000 and overlap == 8 << 20
cfgl = data['adsp_dtb.b01']
assert sha(cfgl) == 'f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94'
assert cfgl[:4] == b'CFGL' and struct.unpack_from('<II', cfgl, 16) == (60, 8316)
assert struct.unpack_from('<I', cfgl, 40)[0] == 11 and cfgl[44:55] == b'default.dtb'
fdt = struct.unpack_from('>10I', cfgl, 60)
assert fdt[0] == 0xd00dfeed and fdt[1] == 8315 and cfgl[60+fdt[1]:] == b'\0'
tree = cfgl[60:60+fdt[1]]
a.output.mkdir()
path = a.output/'charger-default.dtb'
path.write_bytes(tree)
dtc = shutil.which('dtc')
assert dtc
result = subprocess.run([dtc, '-I', 'dtb', '-O', 'dts', '-o', str(a.output/'charger-default.dts'), str(path)],
                        capture_output=True, text=True)
(a.output/'dtc.log').write_text(result.stderr)
assert result.returncode == 0
version = json.loads(data['verinfo/ver_info.txt'])
report = {
    'passed': True, 'native_operations_by_inspector': 0,
    'native_controller_UTC': receipt['created_utc'], 'phone_session': receipt['session'],
    'FAT_geometry': native['FAT_geometry'], 'files': {name: {'bytes': len(value), 'sha256': sha(value)} for name, value in data.items()},
    'images': images, 'compiled_descriptors': compiled, 'ADSP_Demura_overlap_bytes': overlap,
    'installed_PIL_config_sha256': sha(config_bytes), 'configured_images': configured_images,
    'map_source': {'observed_sha256': sha(source), 'G80_build_manifest_sha256': expected_source_hash,
                   'whole_file_matches_G80_build_manifest': sha(source) == expected_source_hash,
                   'two_selected_descriptors_match_compiled_bytes': True},
    'all_64_ADSP_file_extents_in_physical_partition': len(native['ADSP_extent_proofs']) == 64 and all(row.get('physical_extents_in_bounds') for row in native['ADSP_extent_proofs'].values()),
    'firmware_reported_versions': version,
    'CFGL': {'observed_entry': 'default.dtb', 'data_offset': 60, 'entry_bytes': 8316,
             'FDT_bytes': len(tree), 'FDT_sha256': sha(tree), 'DTC_pass': True, 'active_selection_proven': False},
    'limits': ['Compiled descriptor observations are not a live memory-ownership capture.',
               'The current source snapshot differs from the G80 manifest; compiled bytes establish the two descriptors independently.',
               'The CFGL entry is included data; selection and OEM overrides remain unproven.',
               'Filesystem geometry remains oversized; bounded metadata reads do not repair or qualify a mount.',
               'Firmware version strings do not prove the physical Wi-Fi/BT silicon or PCIe ID.',
               'No signature authentication or DSP start occurs.'],
}
(a.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({'passed': True, 'metadata_files': len(data), 'ADSP_span': images[0]['load_span'],
                  'overlap_bytes': overlap, 'native_operations': 0}))
