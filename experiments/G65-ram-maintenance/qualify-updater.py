"""Stage a reproducible updater, test native refusals, retain protected hashes."""
from pathlib import Path
import base64,hashlib,json,struct
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-ram.json').read_text());t=json.loads((W/'RAM-transfer-proof.json').read_text())
assert b['phase']=='fresh_boot_root_and_all_protected_metadata_verified'
assert t['phase']=='RAM_journal_large_transfer_and_roundtrip_verified'
m=json.loads((P/'updater-01/build.json').read_text());m2=json.loads((P/'updater-reproduction-01/build.json').read_text())
assert m['binary_sha256']==m2['binary_sha256'] and m['sources_sha256']==m2['sources_sha256']
assert m['physical_root_updater_source_unchanged'] and m['passed_tests']==36
R=Relay('updater-native-qualification.json',phone_session=b['session']);s=R.s
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok' and r.get('exit_code',0)==0,r;return r
exe=P/'updater-01/G65-disktool-r6.exe';h=hashlib.sha256(exe.read_bytes()).hexdigest();assert h==m['binary_sha256']
assert op('stage-reproduced-updater','put',file=exe,path=exe.name)['sha256']==h
remote=r'X:\OpenG17\payloads\G65-disktool-r6.exe'
assert op('native-updater-hash','hash',path=remote)['sha256']==h
header=bytearray(128);header[:8]=b'MSWIM\0\0\0'
for off,value in [(8,208),(44,1),(120,1)]:struct.pack_into('<I',header,off,value)
v=base64.b64encode(header).decode()
bad={'version':'G21-trial-wim-v1','name':'G20-acpi-canary.wim','before_bytes':4096,'after_bytes':4096,'before_sha256':'0'*64,'after_sha256':'1'*64,'changes':[{'offset':0,'before':v,'after':v}],'tail':''}
p=P/'unqualified-image-pair.json';p.write_text(json.dumps(bad))
assert op('stage-small-refusal-fixture','put',file=p,path='G65-unqualified-pair.json')['sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
for label,plan,journal,expected in [
 ('refuse-physical-plan',r'C:\OpenG17\payloads\G65-forward.json',r'X:\OpenG17\payloads\G65-refused.journal.json','requires a flat RAM payload JSON path'),
 ('refuse-plan-journal-alias',r'X:\OpenG17\payloads\G65-alias.json',r'x:\openg17\payloads\G65-ALIAS.JSON','distinct RAM plan and journal required'),
 ('refuse-unqualified-image-pair',r'X:\OpenG17\payloads\G65-unqualified-pair.json',r'X:\OpenG17\payloads\G65-refused.journal.json','RAM updater accepts only the retained G64 image pair')]:
 r=R.op(label,'phone','exec',argv=[remote,'update-trial-wim-ram',plan,journal,'--update-only-inactive-trial-file-from-ram'])
 assert r['status']=='error' and r['exit_code']==1 and expected in r['output'],r
 s.setdefault('native_refusals',{})[label]=expected;R.persist()
for target,expected in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
 r=op('full-'+target+'-hash','exec',argv=[remote,'hash',target,'0','201326592'])
 x=json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
 assert x['raw_writes']==0 and x['sha256']==expected
 s[target]=x;R.persist()
r=op('FAT-before-WIM-update','exec',argv=[remote,'hash','userdata','0','268435456'])
x=json.JSONDecoder().raw_decode(r['output'].lstrip())[0];assert x['raw_writes']==0
s.update(phase='reproduced_updater_native_RAM_refusals_and_protected_hashes_verified',
         binary_sha256=h,pure_tests=m['passed_tests'],FAT_before=x,
         all_refusals_precede_writable_file_open=True)
R.persist();print(json.dumps({k:s[k]for k in ['phase','binary_sha256','native_refusals','pure_tests']}),flush=True)
