"""Audit retained G80 source and preparation receipts. No device access."""
from pathlib import Path
import hashlib,json,struct
root=Path(__file__).resolve().parents[2];source=Path(__file__).resolve().parent;e=root/'evidence/G80'
def load(n):return json.loads((e/n).read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
f=load('fat-plan-preparation.json');assert f['image_bytes']==1<<30 and f['sector_bytes']==f['cluster_bytes']==4096 and f['fat_copies_identical'] and f['fsck_exit']==0 and f['files']==77
plan=(source/'G80-pinned-plan.bin').read_bytes();assert len(plan)==1048832 and hashlib.sha256(plan).hexdigest()==f['plan_sha256'];assert plan[:8]==b'OP80P01\0';assert struct.unpack_from('<4I',plan,8)==(1,4096,65536,16384)
assert plan[48:80].hex()==f['before_sha256'] and plan[80:112].hex()==f['after_sha256']
assert sum(plan[i:i+32]!=plan[i+32:i+64] for i in range(256,len(plan),64))==10523
b=load('bcd-semantic-audit.json');assert b['result']=='pass' and b['before_keys']==b['after_keys']==97 and len(b['changed_keys'])==11 and b['full_OS_device_and_osdevice_unchanged'] and b['PE_default_and_displayorder_pinned'] and b['unsafe_deploy_entry_not_in_menu']
g=load('gpt-plan-proof.json');assert g['changed_bytes']==48 and [r['changed_bytes'] for r in g['regions']]==[0,8,16,8,16]
for variant,mode in [('apply',13),('undo',14),('normal',9)]:
 v=load('firmware-'+variant+'.json');assert v['mode']==mode and v['firmware_files']==216 and v['sources_verified']==36 and v['FD_bytes']==4<<20
 assert v['RamPartitionDxe']=='byte_identical'
 for name in ['UsbMsdDxe','UsbfnDwc3Dxe','UFSDxe']:assert v[name]=='binary and FFS identical to baseline'
 assert len(v['added'])==1 and '2e037fd2' in v['added'][0]
changes=load('firmware-source-changes.json')
for name in ['OpenBootRepairRecovery.c','OpenPinnedBlockIo.c','OpenPinnedBlockIo.h','OpenG80GptTypeMigration.c','OpenG80GptTypeMigration.h','OpenSha256.h','OpenPinnedPlanIdentity.h','OpenG80GoldenData.h']:
 assert sha(source/name)==changes['Platforms/AndromedaPkg/Library/DeviceBootManagerLib/'+name]['new'],name
for n in ['ReadOnlyBlockIo.c','ReadOnlyBlockIo.h','OpenScsiWriteProtect.h']:assert (source/n).read_bytes()==(source.parent/'G79-controlled-recovery'/n).read_bytes()
q=load('native-qualification.json');assert all(q[k]['exit_code']==0 for k in ['compile_pinned','pinned_failure_injection','actual_firmware_gpt_failure_injection','host_protocol']);assert '1063 checks' in q['pinned_failure_injection']['output'] and '88 actual-source runs' in q['actual_firmware_gpt_failure_injection']['output']
for n in ['OpenPinnedBlockIo.c','OpenPinnedBlockIo.h','OpenG80GptTypeMigration.c','OpenSha256.h','test-pinned.c','test-gpt.c','scsi-prefix/protocol.go','scsi-prefix/main_windows.go','scsi-prefix/source_windows.go']:
 assert sha(source/n)==q['source_sha256'][n],n
release=load('release.json');assert release['plan_sha256']==f['plan_sha256'];entries={v['name']:v for v in release['files']};assert entries['boot-prefix.img']['sha256']==f['after_sha256'] and entries['undo/original-prefix.img']['sha256']==f['before_sha256']
for v in ['apply','undo','normal']:assert entries[release['images'][v]]['sha256']==load('firmware-'+v+'.json')['image_sha256']
s=load('release-staged.json');assert s['status']=='ok' and s['exit_code']==0 and 'G80_PREFLIGHT_PASS' in s['output'] and '64KiB SCSI read qualified' in s['output']
assert load('debug-verified-r3.json')['status']=='ok'
print('G80 source, exact hash map, FAT/BCD/GPT scope, native fault tests, firmware and staged-release audit PASS.')
print('This preparation audit does not establish native writes, hot handoff, repaired setup, desktop or full-OS control.')
