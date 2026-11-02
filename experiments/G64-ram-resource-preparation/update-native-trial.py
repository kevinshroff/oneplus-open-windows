"""Qualified file-only inactive-WIM transaction, never replay after timeout."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('native-WIM-update.json');s=R.s
q=json.loads((W/'WIM-qualified.json').read_text());b=json.loads((W/'native-preflight-v2.json').read_text())
assert q['phase']=='retained_verified_audited_trial_and_delta'and q['both_directions_locally_reconstructed']
assert b['phase']=='fresh_original_G17_protected_metadata_and_FAT_verified'and b['all_six_GPTs_byte_identical']
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def disk(label,args,tool='G18-disktool-r4.exe'):
 r=op(label,'exec',argv=['X:\\OpenG17\\payloads\\'+tool,*args],timeout=180)
 return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
assert op('updater-hash','hash',path=r'X:\OpenG17\payloads\G21-disktool-r5.exe')['sha256']=='db925d3106b153f9688cfaef4b08e15851dc3c8939e4f6652ea754b2774e51c1'
x=disk('preimage',['filehash',r'X:\OpenG18\G20-acpi-canary.wim']);assert x['sha256']==q['source_sha256']and x['bytes']==b['inactive_trial_source']['bytes']
for name in ['G64-wim-forward.json','G64-wim-inverse.json']:
 p=P/name;h=hashlib.sha256(p.read_bytes()).hexdigest()
 assert op('stage-'+name,'put',file=p,path=name)['sha256']==h
 assert op('hash-'+name,'hash',path='X:\\OpenG17\\payloads\\'+name)['sha256']==h
journal=r'X:\OpenG17\payloads\G64-WIM-update.journal.json'
s.update(phase='update_requested',native_journal=journal);R.persist()
x=disk('single-file-update',['update-trial-wim',r'X:\OpenG17\payloads\G64-wim-forward.json',journal,'--update-only-inactive-trial-file'],tool='G21-disktool-r5.exe')
assert x['phase']=='verified'and x['after_sha256']==q['sha256']and x['identity']['raw_writes']==0
s['update_result']=x;R.persist()
local=P/'native-WIM-update.journal.json';op('retain-native-journal','get',path=journal,save=local)
j=json.loads(local.read_text());assert j['phase']=='verified'and j['plan']==json.loads((P/'G64-wim-forward.json').read_text())
x=disk('full-postimage',['filehash',r'X:\OpenG18\G20-acpi-canary.wim']);assert x['sha256']==q['sha256']and x['bytes']==q['bytes']
fat=disk('FAT-remains-preimage',['hash','userdata','0','268435456']);assert fat['sha256']==b['sha256']and fat['raw_writes']==0
s.update(phase='native_trial_WIM_update_verified',trial_image_sha256=q['sha256'],full_readback=x,FAT_preimage_unchanged=True,raw_writes=0);R.persist();print(json.dumps({k:s[k]for k in ['phase','trial_image_sha256','FAT_preimage_unchanged','raw_writes']}),flush=True)
