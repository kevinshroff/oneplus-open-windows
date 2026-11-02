"""Repeat the retained transfer only after proving the agent journal is in RAM."""
from pathlib import Path
import hashlib,json
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private'
b=json.loads((W/'boot-ram.json').read_text())
assert b['phase']=='fresh_boot_root_and_all_protected_metadata_verified'
assert b['root']['x_is_ramdisk'] and b['all_six_GPTs_byte_identical_to_baseline']
R=Relay('RAM-transfer-proof.json',phone_session=b['session']);s=R.s
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw)
 assert r['status']=='ok' and r.get('exit_code',0)==0,r
 return r
cfg=P/'RAM-agent-config.json'
op('retain-private-agent-config','get',path=r'X:\OpenG17\agent.json',save=cfg)
cfg.chmod(0o600)
c=json.loads(cfg.read_text())
assert c['node']=='phone'
assert c['state_dir'].lower()==r'x:\openg17\state'
assert c['payload_dir'].lower()==r'x:\openg17\payloads'
s.update(agent_state_directory=c['state_dir'],agent_payload_directory=c['payload_dir'],
         system_root_is_RAM=True,configuration_secrets_exported=False)
R.persist()
source=W.parent/'ram-handoff-G64/private/G64-wim-inverse.json'
assert source.stat().st_size==2229676
h=hashlib.sha256(source.read_bytes()).hexdigest()
remote=r'X:\OpenG17\payloads\G65-journal-transfer-proof.json'
assert op('single-repeat-large-PUT','put',file=source,path='G65-journal-transfer-proof.json')['sha256']==h
assert op('native-full-hash','hash',path=remote)['sha256']==h
got=op('roundtrip-exact-large-file','get',path=remote)
assert got['sha256']==h and got['data_bytes']==source.stat().st_size
s.update(phase='RAM_journal_large_transfer_and_roundtrip_verified',
         transferred_bytes=source.stat().st_size,sha256=h,
         source='exact retained G64 inverse plan from the stalled physical-root transfer',
         physical_partition_write_calls=0)
R.persist()
print(json.dumps({k:s[k] for k in ['phase','transferred_bytes','sha256','physical_partition_write_calls']}),flush=True)
