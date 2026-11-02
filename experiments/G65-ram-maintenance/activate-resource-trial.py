"""Arm the separately audited resource image once, preserving the G17 default."""
from pathlib import Path
import hashlib,json
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private'
load=lambda n:json.loads((W/n).read_text())
boot=load('boot-ram.json');prep=load('resource-boot-preparation.json');fresh=load('fresh-trial-FAT-backup.json');u=load('native-WIM-update.json')
assert boot['phase']=='fresh_boot_root_and_all_protected_metadata_verified' and boot['root']['x_is_ramdisk']
assert prep['phase']=='offline_one_time_BCD_and_FAT_plan_audited_not_activated'
assert prep['G17_default_and_all_original_BCD_keys_values_unchanged'] and prep['inverse_exactly_restores_fresh_FAT']
assert prep['loader']=='{98a7ea09-cd06-11f1-9482-c0a810591275}' and 0<prep['changed_sectors']<=1024
assert fresh['phase']=='fresh_post_maintenance_FAT_retained_and_verified' and fresh['sha256']==prep['before_sha256']
assert u['phase']=='native_RAM_controlled_trial_WIM_update_and_full_readback_verified'
assert u['full_WIM_readback_sha256']=='cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7'
R=Relay('resource-activation.json',phone_session=boot['session']);s=R.s
def op(label,node,action,**kw):
 r=R.op(label,node,action,**kw);assert r['status']=='ok' and r.get('exit_code',0)==0,r;return r
tool=r'X:\OpenG17\payloads\G65-disktool-r6.exe'
assert op('updater-hash','phone','hash',path=tool)['sha256']==load('updater-native-qualification.json')['binary_sha256']
ps="$ErrorActionPreference='Stop';$e=@(Get-NetUDPEndpoint -LocalPort 50000);if($e.Count -ne 1){throw 'Need one existing debugger listener'};$p=Get-Process -Id $e[0].OwningProcess;if($p.ProcessName -ne 'EngHost'){throw 'Listener owner differs'};$s=Get-AuthenticodeSignature -LiteralPath $p.Path;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Debugger publisher differs'};@{PID=$p.Id;publisher=$s.SignerCertificate.Subject;existing_listener=$true}|ConvertTo-Json -Compress"
op('existing-debugger-listener','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps])
for name,key in [('G65v3-FAT-onetime.json','plan_sha256'),('G65v3-FAT-onetime-inverse.json','inverse_sha256')]:
 p=P/name;h=hashlib.sha256(p.read_bytes()).hexdigest();assert h==prep[key]
 assert op('stage-'+name,'phone','put',file=p,path=name)['sha256']==h
 assert op('hash-'+name,'phone','hash',path='X:\\OpenG17\\payloads\\'+name)['sha256']==h
def native(label,args):
 r=op(label,'phone','exec',argv=[tool,*args],timeout=180)
 return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
x=native('fresh-FAT-preimage',['hash','userdata','0','268435456']);assert x['sha256']==prep['before_sha256'] and x['raw_writes']==0
journal=r'X:\OpenG17\payloads\G65v3-FAT.journal.json'
s.update(phase='resource_one_time_FAT_apply_requested',starting_session=boot['session'],
         loader=prep['loader'],native_journal=journal,candidate_WIM_sha256=u['full_WIM_readback_sha256'])
R.persist()
x=native('single-resource-FAT-transaction',['apply-fat',r'X:\OpenG17\payloads\G65v3-FAT-onetime.json',journal,'--write-userdata-prefix'])
assert x['phase']=='verified' and x['after_sha256']==prep['after_sha256'] and x['sectors_written']==prep['changed_sectors']
s['FAT_apply']=x;R.persist()
local=P/'native-resource-FAT.journal.json';op('retain-resource-FAT-journal','phone','get',path=journal,save=local)
j=json.loads(local.read_text());assert j['phase']=='verified' and j['plan']==json.loads((P/'G65v3-FAT-onetime.json').read_text())
for target,expected in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
 x=native(target+'-after-resource-FAT',['hash',target,'0','201326592']);assert x['sha256']==expected and x['raw_writes']==0
 s[target]=x;R.persist()
s['reboot']=op('single-resource-reboot','phone','reboot')
s['phase']='selected_resource_RAM_reboot_acknowledged';R.persist();print(s['phase'],flush=True)
