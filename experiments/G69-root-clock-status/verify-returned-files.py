"""Verify the original stack, full protected boot images and expected maintenance/trial WIMs."""
from pathlib import Path
import json
from relay import Relay
W=Path(__file__).resolve().parent
b=json.loads((W/'boot-physical.json').read_text())
assert b['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and not b['root']['x_is_ramdisk']and b['all_six_GPTs_byte_identical_to_baseline']
R=Relay('returned-files.json',phone_session=b['session']);s=R.s
def op(label,action,**kw):
    r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def disk(label,args):
    r=op(label,'exec',argv=[r'X:\OpenG17\payloads\G18-disktool-r4.exe',*args],timeout=180)
    return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert op('qualified-reader-hash','hash',path=r'X:\OpenG17\payloads\G18-disktool-r4.exe')['sha256']=='7b944d4bf025423ab213b4ad133f8f9b59acd1e787b1875b551bc9735dfc902f'
for name,expected in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
    x=disk('full-'+name,['hash',name,'0','201326592']);assert x['sha256']==expected and x['raw_writes']==0;s[name]=x;R.persist()
for name,path,expected in [
    ('G18-maintenance',r'X:\OpenG18\G18-maintenance.wim','1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'),
    ('inactive-trial',r'X:\OpenG18\G20-acpi-canary.wim','de32242eb883ed45d1d29db52190ef5161da6845cccbad40c7cf821a0866b9dc')]:
    x=disk(name,['filehash',path]);assert x['sha256']==expected;s[name]=x;R.persist()
r=op('current-Ntfs-full-file-hash','hash',path=r'X:\Windows\System32\drivers\Ntfs.sys');assert r['sha256']=='ff70d93b72513a850c86d914aeebedbaf8abf1d9cd26ece81f16cedc5dfbc11a';s['Ntfs_native_file_sha256']=r['sha256'];R.persist()
r=op('original-stack-audit','exec',argv=[r'X:\OpenG17\payloads\G59-cleanup.exe','audit']);a=json.loads(r['output'])['result'];assert a==json.loads((W.parent/'resources-G63/normal-G17-refusal.json').read_text())['audit_after'];s['software_audit']=a;R.persist()
r=R.op('RAM-recorder-service-registry-key-absent-after-return','phone','exec',argv=[r'X:\Windows\System32\reg.exe','query',r'HKLM\SYSTEM\CurrentControlSet\Services\OpenG69'])
assert r['status']=='error' and r['exit_code']==1 and 'The system was unable to find the specified registry key or value.' in r['output'],r
s['RAM_clock_service_absent_after_return']=True;R.persist()
r=op('post-recovery-health','probe');assert r['detail']['cpus']==8 and r['detail']['arch']=='arm64'
s.update(phase='normal_G17_recovery_full_boot_WIM_and_stack_hashes_verified',session=b['session'],original_software_stack_verified=True,audited_inactive_trial_WIM_verified=True,normal_physical_root_and_DSDT_verified=True,all_six_GPTs_and_138_partitions_verified=True,raw_partition_writes=0);R.persist();print(json.dumps({k:s[k]for k in ['phase','session','original_software_stack_verified','audited_inactive_trial_WIM_verified']}),flush=True)
