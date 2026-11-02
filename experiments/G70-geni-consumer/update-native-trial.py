"""One durable RAM-controlled inactive-WIM update, with native full readback."""
from pathlib import Path
import hashlib,json
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private';B=W
boot=json.loads((W/'boot-maintenance.json').read_text());qual=json.loads((W/'updater-native-qualification.json').read_text());image=json.loads((B/'WIM-qualified.json').read_text())
assert boot['phase']=='fresh_boot_root_and_all_protected_metadata_verified' and boot['root']['x_is_ramdisk']
assert qual['phase']=='reproduced_updater_native_RAM_refusals_and_protected_hashes_verified'
assert image['phase']=='retained_verified_audited_trial_and_delta' and image['both_directions_locally_reconstructed']
R=Relay('native-WIM-update.json',phone_session=boot['session']);s=R.s
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok' and r.get('exit_code',0)==0,r;return r
tool=r'X:\OpenG17\payloads\G70-disktool-r8.exe'
assert op('qualified-updater-hash','hash',path=tool)['sha256']==qual['binary_sha256']
for name in ['G70-wim-inverse.json','G70-wim-forward.json']:
 p=B/'private'/name;h=hashlib.sha256(p.read_bytes()).hexdigest()
 assert p.stat().st_size==image['forward_plan_bytes']
 assert op('stage-'+name,'put',file=p,path=name)['sha256']==h
 assert op('native-hash-'+name,'hash',path='X:\\OpenG17\\payloads\\'+name)['sha256']==h
journal=r'X:\OpenG17\payloads\G70-WIM-update.journal.json'
s.update(phase='single_RAM_controlled_inactive_WIM_update_requested',native_journal=journal,
         source_sha256=image['source_sha256'],candidate_sha256=image['sha256'])
R.persist()
r=op('single-inactive-file-update','exec',argv=[tool,'update-trial-wim-ram',r'X:\OpenG17\payloads\G70-wim-forward.json',journal,'--update-only-inactive-trial-file-from-ram'],timeout=180)
x=json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert x['phase']=='verified' and x['after_sha256']==image['sha256'] and x['after_bytes']==image['bytes']
assert x['before_sha256']==image['source_sha256'] and x['identity']['raw_writes']==0 and x['identity']['journal_root']=='proved RAM'
s['update_result']=x;R.persist()
local=P/'native-WIM-update.journal.json';op('retain-native-WIM-journal','get',path=journal,save=local)
j=json.loads(local.read_text())
assert j['phase']=='verified' and j['plan']==json.loads((B/'private/G70-wim-forward.json').read_text())
assert j['identity']==x['identity']
r=op('FAT-after-file-update','exec',argv=[tool,'hash','userdata','0','268435456'])
fat=json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert fat['sha256']==qual['FAT_before']['sha256'] and fat['raw_writes']==0
s.update(phase='native_RAM_controlled_trial_WIM_update_and_full_readback_verified',
         full_WIM_readback_sha256=x['after_sha256'],FAT_unchanged=True,raw_partition_writes=0)
R.persist()
print(json.dumps({k:s[k]for k in ['phase','full_WIM_readback_sha256','FAT_unchanged','raw_partition_writes']}),flush=True)
