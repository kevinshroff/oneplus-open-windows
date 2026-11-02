"""Arm the audited one-time sequence and request exactly one recorded reboot."""
from pathlib import Path
import hashlib,json
from relay import Relay,SESSIONS
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('controller-activation.json');s=R.s
load=lambda p:json.loads((W/p).read_text())
plan=load('one-time-boot-preparation.json');base=load('boot-preactivation.json');native=load('native-WIM-update.json');q=load('WIM-qualified.json');dbg=load('debugger-preflight.json')
assert plan['phase']=='offline_one_time_BCD_and_FAT_plan_audited_not_activated'and plan['G17_default_and_all_original_BCD_keys_values_unchanged']
assert 0<plan['changed_sectors']<=1024
assert base['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and base['all_six_GPTs_byte_identical_to_baseline']and not base['root']['x_is_ramdisk']
assert base['session']==SESSIONS['phone']and base['API_DSDT']['sha256']=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
assert native['phase']=='native_trial_WIM_update_verified'
assert dbg['session']==base['session']and dbg['target_running']and dbg['existing_breakpoints']==0
def op(label,node,action,**kw):
    r=R.op(label,node,action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def disk(label,args):
    r=op(label,'phone','exec',argv=[r'X:\OpenG17\payloads\G18-disktool-r4.exe',*args],timeout=180)
    return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
ps="$ErrorActionPreference='Stop';if(@(Get-NetUDPEndpoint -LocalPort 50000).Count -eq 0){throw 'Existing debugger listener absent'};Write-Output 'Existing debugger listener verified'"
op('existing-debugger-listener','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps])
for name,key in [('G64-FAT-onetime.json','plan_sha256'),('G64-FAT-onetime-inverse.json','inverse_sha256')]:
    p=P/name;assert hashlib.sha256(p.read_bytes()).hexdigest()==plan[key]
    assert op('stage-'+name,'phone','put',file=p,path=name)['sha256']==plan[key]
    assert op('hash-'+name,'phone','hash',path='X:\\OpenG17\\payloads\\'+name)['sha256']==plan[key]
x=disk('image-preflight',['filehash',r'X:\OpenG18\G20-acpi-canary.wim']);assert x['sha256']==q['sha256']and x['bytes']==q['bytes']
x=disk('FAT-preimage',['hash','userdata','0','268435456']);assert x['sha256']==plan['before_sha256']and x['raw_writes']==0
s.update(phase='one_time_FAT_apply_requested',starting_session=base['session'],trial_WIM_sha256=q['sha256'],loader=plan['loader'],native_journal=r'X:\OpenG17\payloads\G64-FAT.journal.json');R.persist()
x=disk('single-FAT-transaction',['apply-fat',r'X:\OpenG17\payloads\G64-FAT-onetime.json',s['native_journal'],'--write-userdata-prefix'])
assert x['phase']=='verified'and x['sectors_written']==plan['changed_sectors']and x['after_sha256']==plan['after_sha256']
s['FAT_apply']=x;s['phase']='one_time_FAT_readback_verified';R.persist()
local=P/'native-FAT.journal.json';op('retain-FAT-journal','phone','get',path=s['native_journal'],save=local)
j=json.loads(local.read_text());assert j['phase']=='verified'and j['plan']==json.loads((P/'G64-FAT-onetime.json').read_text())and j['identity']['gpt_header_sha256']==x['identity']['gpt_header_sha256']
for name,expected in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
    x=disk(name+'-before-reboot',['hash',name,'0','201326592']);assert x['sha256']==expected and x['raw_writes']==0
    s[name]=x;R.persist()
s['phase']='journal_saved_and_protected_boot_hashes_verified';R.persist()
s['reboot']=op('single-reboot','phone','reboot');s['phase']='one_time_RAM_reboot_acknowledged';R.persist();print(s['phase'],flush=True)
