"""One recorded sustained native window. Preserve raw capture before decoding.

Resume the same named journal after observation timeouts; never submit a second
powered invocation. The two phases separate read-only preparation from launch.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess,uuid
from relay import Relay
p=argparse.ArgumentParser();p.add_argument('--run',choices=['idle-stop-v2'],default='idle-stop-v2');p.add_argument('--phase',choices=['prepare','launch','collect'],required=True);a=p.parse_args();W=Path(__file__).resolve().parent;B=W.parent/'stream-G59';suffix='-'+a.run;R=Relay('live-native'+suffix+'.json');N=Relay('native-qualification'+suffix+'.json');s=R.s;base=r'X:\OpenG17\payloads';admin=base+r'\G60-idle-admin-v2.exe';capture=base+r'\G60-idle-stop-capture';receiver=base+r'\G59-receiver.exe';out=W/('private/live-native'+suffix);out.mkdir(exist_ok=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(label,argv):
 r=R.op(label,'phone','exec',argv=argv);assert r['status']=='ok'and r.get('exit_code',0)==0,r;v=json.loads(r['output']);assert v['ok'],v;return v['result']
if a.phase=='prepare':
 assert N.s['phase']=='Windows_HID_parser_physical_axes_and_owned_tree_verified_no_input'
 for name,remote in [('admin',admin),('receiver',receiver)]:
  m=json.loads(((W/'private/idle-admin-02/build.json')if name=='admin'else B/'private/receiver-01/build.json').read_text());assert R.op('hash-'+name,'phone','hash',path=remote)['sha256']==m['binary_sha256']
 expected=json.loads((W/'private/idle-admin-02/build.json').read_text())['binary_sha256'];assert R.op('hash-guarded-admin','phone','hash',path=capture+r'\G59-admin.exe')['sha256']==expected
 s['source_before']=run('source-before',[admin,'status']);s['session_before']=run('session-before',[admin,'session']);s['snapshot_before']=run('snapshot-before',[admin,'snapshot']);s['pmic_before']=run('pmic-before',[admin,'pmic']);R.persist()
 assert s['source_before']['live_attempts']==s['source_before']['accepted_mask']==0 and s['session_before']['state']==s['session_before']['starts']==0
 v=s['pmic_before'];assert v['operation_code']==0 and v['attempt']==1 and v['fixed_registers_unchanged']==1 and v['pmic_status_raw']==0x43 and v['configuration']==[8,7,0,0,7,7,0,0]
 if 'token'not in s:s.update(token=uuid.uuid4().hex,trial_mode='stop',cancellation_input_expectation='idle',max_powered_invocations=1,minimum_poll_cycles=1000,capture_dir=capture);R.persist()
 s['phase']='read_only_preparation_passed_no_powered_start';R.persist()
elif a.phase=='launch':
 assert N.s['phase']=='Windows_HID_parser_physical_axes_and_owned_tree_verified_no_input'and s['phase']=='read_only_preparation_passed_no_powered_start'
 admin_sha=json.loads((W/'private/idle-admin-02/build.json').read_text())['binary_sha256']
 s['window_receipt']=R.op('single-window-job','phone','exec',argv=[receiver,'live',capture,s['token'],capture+r'\G59-admin.exe',admin_sha,'stop'],timeout=70);s['phase']='recorded_window_returned_never_rearm';R.persist()
elif a.phase=='collect':
 assert 'single-window-job'in s['jobs'],'Observe the recorded launch before collecting'
 for name,ext in [('ready','.json'),('qualification','.json'),('events','.jsonl'),('done','.json'),('power','.bin')]:
  f=out/(name+ext);r=R.op('get-'+name,'phone','get',path=capture+'\\G59-receiver-'+s['token']+'-'+name+ext,save=f if not f.exists()else None)
  if r['status']=='ok':assert f.exists()and sha(f)==r['sha256']
 assert (out/'power.bin').exists()and(out/'power.bin').stat().st_size==959896,'No saved kernel result: inspect session without repeating PMIC or START'
 s['source_after']=run('source-after',[admin,'status']);s['session_after']=run('session-after',[admin,'session']);s['snapshot_after']=run('snapshot-after',[admin,'snapshot']);s['pmic_after']=run('pmic-after',[admin,'pmic']);R.persist()
 q=subprocess.run([str((B/'private/hardware-abi-02/decoder').resolve()),str((out/'power.bin').resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,q.stderr;v=json.loads(q.stdout);assert v['ok'];d=v['result'];t=d['touch'];pm=s['pmic_after']
 # The raw959896-byte file is authoritative. Avoid storing the many-megabyte
 # JSON rendering of the bounded MMIO tail; decode it on demand.
 s['hardware_and_power_restoration_verified']=d['restored']==d['fixed_registers_unchanged']==d['safe_release']==d['spi']['restored']==d['spi']['engine']['restored']==t['restored']==1 and d['restore_error']==d['spi']['restore_error']==d['spi']['engine']['restore_error']==t['restore_error']==0 and pm['operation_code']==0 and pm['fixed_registers_unchanged']==1 and pm['pmic_status_raw']==0x43 and pm['configuration']==s['pmic_before']['configuration']
 before=s['snapshot_before']['values'];after=s['snapshot_after']['values'];assert len(before)==len(after)==50 and all(b['name']==c['name']and b['address']==c['address']for b,c in zip(before,after))
 s['fixed50_comparison']=[{'index':i,'name':b['name'],'before':b['value'],'after':c['value']}for i,(b,c)in enumerate(zip(before,after))]
 assert before[12]['value']in(0,7)and after[12]['value']in(0,7)
 s['fixed50_exact']=all(r['before']==r['after']for r in s['fixed50_comparison'])
 s['hardware_and_power_restoration_verified']=s['hardware_and_power_restoration_verified']and all(r['before']==r['after']for r in s['fixed50_comparison']if r['index']!=12)
 s['phase']='capture_preserved_restoration_requires_analysis';R.persist();assert s['hardware_and_power_restoration_verified']
 state=s['source_after'];owner=s['session_after'];poll=t['poll']
 s['summary']={'driver_session':owner,'hardware_restored':True,'Windows_input_reports':state['reports_submitted'],'raw_sha256':sha(out/'power.bin'),'poll':{k:v for k,v in poll.items()if k not in ['records','wires']},'owner_MMIO_trace_total':t['trace_total'],'owner_MMIO_trace_retained':len(t['trace']),'touch_register_reads':t['register_reads'],'touch_register_write_attempts':t['register_write_attempts'],'permanent_touch_qualified':False};R.persist()
 assert owner['state']==3 and owner['starts']==owner['hardware_calls']==owner['result_ready']==owner['thread_joined']==1 and owner['outcome']==2 and owner['stop_reason']==1 and owner['stop_seen']>=1 and owner['stop_requests']==1
 assert d['operation_code']==6 and t['operation_code']==21 and poll['operation_code']==10 and poll['limit']==2500 and 1000<=poll['cycles']<2500 and d['restored']==1
 assert state['live_attempts']==state['stop_attempts']==1 and state['live_complete']==state['accepted_mask']==0 and state['live_error']==6
 ready=json.loads((out/'ready.json').read_text());done=json.loads((out/'done.json').read_text());qual=json.loads((out/'qualification.json').read_text());assert ready['Token']==done['token']==s['token']and ready['TrialMode']=='stop'and ready['Foreground']and ready['DPIAware']and done['window_closed']and not done['dropped']and qual['owned_foreground_verified']and qual['DPI_aware']
 assert s['window_receipt']['status']=='ok'and s['window_receipt'].get('exit_code',0)==0 and done['admin']['ExitCode']==0 and not done['admin']['Error'];child=json.loads(done['admin']['Output']);assert child['ok']and child['result']['sha256']==sha(out/'power.bin')and child['result']['driver_session']==owner
 if a.run=='idle-stop-v2':assert state['reports_submitted']==state['reports_accepted']==state['accepted_generation']==state['stop_accepted']==0 and not (out/'events.jsonl').read_bytes()
 assert child['result']['stop_at_phase']==9 and child['result']['stop_at_cycle']>=1000 and child['result']['cancellation_input_expectation']=='idle'
 s['summary']['stop_to_worker_finish_us']=owner['end_us']-owner['stop_us'];s['summary']['stop_at_cycle']=child['result']['stop_at_cycle'];s['summary']['idle_input_expected']=True
 s['phase']='one_native_idle_poll_cancellation_and_restoration_qualified';R.persist();N.s['phase']='native_idle_poll_cancellation_completed';N.s['sustained_summary']=s['summary'];N.persist()
print(json.dumps({'phase':s.get('phase'),'summary':s.get('summary')}))
