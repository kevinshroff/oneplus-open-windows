"""Audit exported G79 source and sanitized receipts; no device access or writes."""
from pathlib import Path
import hashlib
import json

root = Path(__file__).resolve().parents[2]
source = Path(__file__).resolve().parent
evidence = root / 'evidence/G79'

def read(name):
    return json.loads((evidence / name).read_text())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

build = read('firmware-verification-usb2-ro.json')
assert build['mode'] == 12 and build['sources_verified'] == 26
assert build['firmware_files'] == 215 and build['source_raw_write_forwarders'] == 0
assert build['image_sha256'] == '7c5ec4957adb72f7849d5076496e62ef44688712a07a79a44fd2b242d244c6a7'
assert len(build['changed']) == 4
assert all(any(name in value for name in ('BdsDxe', 'FVMAIN_COMPACT',
           'IdentityAndAuthManagerDxe', 'MuCryptoDxe')) for value in build['changed'])
for name in ('IdentityAndAuthManagerDxe', 'MuCryptoDxe'):
    assert build[name] == 'only_CodeView_GUID_changed'
for name in ('UsbMsdDxe', 'UsbfnDwc3Dxe', 'UFSDxe'):
    assert build[name] == 'source_binary_identical; FFS unchanged'
assert build['RamPartitionDxe'] == 'byte_identical'

changes = read('firmware-source-changes.json')
for name in ('OpenReadOnlyRecovery.c', 'OpenScsiWriteProtect.h',
             'ReadOnlyBlockIo.h', 'ReadOnlyBlockIo.c'):
    key = 'Platforms/AndromedaPkg/Library/DeviceBootManagerLib/' + name
    assert sha(source / name) == changes[key]['new'], name
assert 'Source->WriteBlocks' not in (source / 'ReadOnlyBlockIo.c').read_text()
ro = read('read-only-native-test.json')
assert ro['checks'] == 2165818 and ro['result'] == 'passed'
assert ro['source_writes'] == ro['source_resets'] == ro['source_flushes'] == 0
assert ro['source_sha256'] == sha(source / 'ReadOnlyBlockIo.c')
scsi = read('scsi-write-protect-native-test.json')
assert scsi['checks'] == 6228 and scsi['result'] == 'pass'
assert scsi['source_sha256'] == sha(source / 'OpenScsiWriteProtect.h')
assert scsi['test_sha256'] == sha(source / 'test-scsi-write-protect.c')

for name in ('usb2-ro-stage-and-boot.json', 'usb2-ro-first-ntfs-read.json',
             'usb2-ro-panther-capture.json', 'usb2-ro-hive-capture.json',
             'registry-native-replay-query.json', 'boot-prefix-full-fat-capture.json',
             'ntfs-r4-native-reparse-qualification.json'):
    record = read(name)
    # Stage-and-boot keeps its original multi-operation receipt shape.
    if 'status' in record:
        assert record['status'] == 'ok' and record['exit_code'] == 0, name

query = read('registry-native-replay-query.json')['output']
query = json.loads(query[query.index('{'):])
hives = query['hives']
for hive in hives.values():
    assert hive['header_seq1'] == hive['header_seq2']
system = {key.replace('\\\\', '\\'): val for key, val in hives['SYSTEM']['keys'].items()}
software = {key.replace('\\\\', '\\'): val for key, val in hives['SOFTWARE']['keys'].items()}
assert system[r'Setup\Status\SysprepStatus']['GeneralizationState'] == 6
assert system[r'Setup\Status\ChildCompletion']['setup.exe'] == 1
assert system['Setup']['SetupPhase'] == 4
version = software[r'Microsoft\Windows NT\CurrentVersion']
assert version['CurrentBuildNumber'] == '26300' and version['UBR'] == 9457

manifest = read('ntfs-r4-native-reparse-manifest.json')
records = {item['path']: item for item in manifest['records']}
for path in ('Windows/System32/spbcd.dll', 'Windows/System32/oobe/windeploy.exe',
             'Windows/System32/Sysprep/ActionFiles/Specialize.xml'):
    assert records[path]['status'] == 'unsupported_reparse'
    assert records[path]['reparse_tag'] == '0x80000017'
assert records['Windows/Panther/setuperr.log']['sha256'] == '604de046c5ccab78d8d953255e3540e3d22c7e55c7193a357de4026d4aec10d6'
assert records['Windows/System32/config/SYSTEM']['sha256'] == hives['SYSTEM']['source_sha256'].lower()
assert records['OpenG18']['status'] == 'directory' and records['OpenG18'].get('entries', 0) == 0

backup = read('boot-prefix-1GiB-retained.json')
assert backup['phone_writes'] == 0 and backup['transfer_pieces'] == 13
assert backup['capture']['prefix_bytes'] == 1 << 30
assert backup['capture']['prefix_sha256'] == 'aa4caaf24a8443e6ac35ffe6ccb5c825412f0c3811300fd93178f2cdb801c6b9'
assert backup['prefix256MiB_sha256'] == '131f8f3b49cf42796f294c8b221fe5032cc536f7a0e894bfe55051ab883299df'

print('G79 R5 source and sanitized receipt audit PASS.')
print('Actual read-only recovery, fatal BCD failure, native hive replay, WOF refusal, and retained boot prefix agree.')
print('This audit does not rerun hardware or establish a repaired ESP, setup retry, desktop, or full-OS control.')
