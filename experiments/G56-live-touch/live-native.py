"""One actual live hardware episode, persisted before analysis, never rearmed."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
import argparse
p=argparse.ArgumentParser();p.add_argument('--run',choices=['idle','physical'],default='idle');p.add_argument('--phase',choices=['all','prepare','capture'],default='all');a=p.parse_args();suffix='-physical'if a.run=='physical'else''
W=Path(__file__).resolve().parent;R=Relay('live-native'+suffix+'.json');N=Relay('native-qualification'+suffix+'.json');s=R.s;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=r'X:\OpenG17\payloads';admin=base+r'\G56-admin.exe';receiver=base+r'\G56-receiver.exe';out=W/('private/live-native'+suffix+'-01');out.mkdir(exist_ok=True)
assert N.s['phase']=='Windows_HID_parser_physical_axes_and_owned_tree_verified_no_input'
def run(label,args):
 r=R.op(label,'phone','exec',argv=args);assert r['status']=='ok'and r.get('exit_code',0)==0,r;v=json.loads(r['output']);assert v['ok'],v;return v['result']
for name,folder,remote in [('admin','admin-03',admin),('receiver','receiver-01',receiver)]:
 m=json.loads((W/'private'/folder/'build.json').read_text());r=R.op('hash-'+name,'phone','hash',path=remote);assert r['sha256']==m['binary_sha256']
s['before']=run('status-before',[admin,'status']);R.persist();assert s['before']['live_attempts']==s['before']['accepted_mask']==s['before']['reports_submitted']==0
s['snapshot_before']=run('snapshot-before',[admin,'snapshot']);R.persist()
s['pmic_before']=run('pmic-before',[admin,'pmic']);R.persist();p=s['pmic_before'];assert p['operation_code']==0 and p['fixed_registers_unchanged']==1 and p['pmic_status_raw']==0x43 and p['configuration']==[8,7,0,0,7,7,0,0]
if 'token'not in s:s.update(token=uuid.uuid4().hex,max_powered_invocations=1,window_seconds=12);R.persist()
if a.phase=='prepare':s['phase']='ready_for_single_powered_trial_no_power_yet';R.persist();print(json.dumps({'phase':s['phase']}));raise SystemExit(0)
admin_sha=json.loads((W/'private/admin-03/build.json').read_text())['binary_sha256']
s['window_receipt']=R.op('single-live-window-job','phone','exec',argv=[receiver,'live',base,s['token'],admin,admin_sha],timeout=30);s['phase']='recorded_powered_job_returned_do_not_rearm';R.persist()
# Always preserve available output, even for failed native work. Never submit a
# replacement physical attempt when evidence is weak or observation times out.
for name,suffix in [('ready','ready.json'),('qualification','qualification.json'),('events','events.jsonl'),('done','done.json'),('power','power.bin')]:
 f=out/suffix;r=R.op('get-'+name,'phone','get',path=base+'\\G56-receiver-'+s['token']+'-'+suffix,save=f if not f.exists()else None)
 if r['status']=='ok':assert f.exists()and sha(f)==r['sha256']
s['after']=run('status-after',[admin,'status']);R.persist()
s['snapshot_after']=run('snapshot-after',[admin,'snapshot']);R.persist()
s['pmic_after']=run('pmic-after',[admin,'pmic']);R.persist()
# Decode the exact production Go function offline, without any Windows API.
import subprocess
exe=W/'private/ABI-02/decoder';q=subprocess.run([str(exe.resolve()),str((out/'power.bin').resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,q.stderr;v=json.loads(q.stdout);assert v['ok'],v;d=v['result'];(out/'power-decoded.json').write_text(json.dumps(d,indent=2)+'\n');t=d['touch'];poll=t['poll'];s['hardware_and_power_restoration_verified']=d['restored']==d['fixed_registers_unchanged']==d['safe_release']==t['restored']==d['spi']['restored']==d['spi']['engine']['restored']==1 and d['restore_error']==t['restore_error']==d['spi']['restore_error']==d['spi']['engine']['restore_error']==0
p=s['pmic_after'];s['hardware_and_power_restoration_verified']=s['hardware_and_power_restoration_verified']and p['operation_code']==0 and p['fixed_registers_unchanged']==1 and p['pmic_status_raw']==0x43 and p['configuration']==s['pmic_before']['configuration']
# IRQ/history fields are allowed diagnostic transitions; compare the same exact
# fixed register contract used by the native adapter for all restorable fields.
skip={12};before=s['snapshot_before']['values'];after=s['snapshot_after']['values'];assert len(before)==len(after)==50
assert all(b['name']==a['name']and b['address']==a['address']for b,a in zip(before,after))
assert before[12]['value']in(0,7)and after[12]['value']in(0,7)
s['fixed50_comparison']=[{'index':i,'name':b['name'],'before':b['value'],'after':a['value'],'expected_equal':i not in skip}for i,(b,a)in enumerate(zip(before,after))];assert all(x['before']==x['after']for x in s['fixed50_comparison']if x['expected_equal'])
s['phase']='capture_requires_protocol_analysis_restoration_observed';R.persist();assert s['hardware_and_power_restoration_verified'],'Do not remove owner before hardware/power restoration is understood'
status=s['after'];done=json.loads((out/'done.json').read_text());events=[json.loads(x)for x in(out/'events.jsonl').read_text().splitlines()if x];ready=json.loads((out/'ready.json').read_text());assert ready['Token']==s['token']==done['token']and ready['Foreground']and ready['DPIAware']and done['window_closed']and not done['dropped']
s['summary']={'poll_code':poll['operation_code'],'limit':poll['limit'],'cycles':poll['cycles'],'elapsed_us':poll['elapsed_us'],'contact_records':poll['contact_records'],'request_records':poll['request_records'],'idle_records':poll['idle_records'],'clear_attempts':poll['clear_attempts'],'clear_completed':poll['clear_completed'],'wire_count':poll['wire_count'],'input_status':status,'consumer_events':len(events),'hardware_restored':True,'physical_down_move_up_claimed':False,'continuous_operation_claimed':False};R.persist()
assert d['operation_code']==t['operation_code']==poll['operation_code']==0 and poll['limit']==poll['cycles']==100
assert status['live_attempts']==status['live_complete']==status['stop_attempts']==1 and status['live_error']==status['accepted_mask']==0 and status['reports_accepted']==status['reports_submitted']
assert s['window_receipt']['status']=='ok'and s['window_receipt']['exit_code']==0 and json.loads(s['window_receipt']['output'])['ok']and done['admin']['ExitCode']==0 and not done['admin']['Error']
if status['reports_submitted']==0:assert not events and status['accepted_generation']==0 and not status['stop_accepted'];s['idle_no_phantom_windows_input_verified']=True
s['phase']='one_bounded_native_live_episode_and_hardware_restoration_qualified';R.persist();N.s['phase']='native_live_episode_completed';N.s['live_summary']=s['summary'];N.persist();print(json.dumps({'phase':s['phase'],'summary':s['summary']}))
