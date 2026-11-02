"""Finite G74 OFF-only experiment, with durable non-replayed operation receipts.

The existing hash-pinned G35 SCM helper owns service OpenG35. The new signed
driver creates device OpenG74. Never use G35-specific device IOCTLs with it.
An observation timeout is not permission to queue another load or RUN.
"""
from pathlib import Path
import argparse,base64,hashlib,json,subprocess,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('native.json');s=R.s
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=r'X:\OpenG17\payloads';client=base+r'\G74-client.exe';loader=base+r'\G35-client.exe';driver=base+r'\G74-signed.sys'
signed='e293f7d7b336bce202d391aeaba6397b5281d130956ece0ea37e86f275deb6c9'
clientsha='5dbb714db7980daaaacae317444e4bf452b0a0a4cfc08eea8cface9482094134'
loadersha='466a5db1bb3846d720d1fa165a68a8c3c8f27a06d0ecec9a22c7a95121dfe400'
def persist(phase=None):
 if phase:s['phase']=phase
 R.persist()
def checked(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and not r.get('exit_code',0),r;return r
def execute(label,argv):
 r=checked(label,'exec',argv=argv);v=json.loads(r['output']);assert v['ok'],v;return v.get('result',v)
def qualify_build():
 assert sha(P/'G74-signed.sys')==signed and sha(P/'G74-client.exe')==clientsha
 for dirname in ['compile-01','client-objects-01']:
  j=json.loads((P/dirname/'compile.json').read_text())
  for x in j['objects']:assert sha(W/x['source'])==x['source_sha256']and sha(P/dirname/x['object'])==x['sha256']
  for n,h in j['headers'].items():assert sha(W/n)==h
  assert sha(P/'inputs/g74_binding.h')==j['binding_sha256']
 for dirname,count in [('power-model-01',1196),('adapter-model-02',12372),('client-policy-01',657)]:
  j=json.loads((P/dirname/'tests.json').read_text());assert j['passed']and j['cases']==count and not j['native_operations']
  for n,h in j['source_sha256'].items():assert sha(W/n)==h
 j=json.loads((W/'signature-verification.json').read_text());assert j['signed_driver_sha256']==signed and j['SHA256_Authenticode_digest_matches_verified_CMS_content']and j['all_loadable_sections_byte_identical_before_after_signing']and not j['root_trust_store_changed']
 j=json.loads((W/'reproduce-links.json').read_text());assert j['phase']=='clean_source_objects_and_both_executables_reproduced_byte_identically'and j['full_input_and_output_verification']=={'ok':True,'verified':19}
 assert json.loads((P/'reproduce-01/reproduction.json').read_text())['passed']
 j=json.loads((W/'G17-IRQ-CPU.json').read_text());assert j['passed']and j['case_count']==32 and not j['native_operations']
 j=json.loads((W/'production-delta.json').read_text());assert not j['G59_changed']and not j['other_native_IO_policy_changed']and not j['resource_write_budget_changed']
def token(label):
 s.setdefault('tokens',{})
 if label not in s['tokens']:s['tokens'][label]=uuid.uuid4().hex;persist()
 return s['tokens'][label]
def capture(label,mode,shared_token=None):
 t=shared_token or token(label);remote=base+'\\G74-'+mode+'-'+t+'.bin';local=P/'native'/label
 local=local.with_suffix('.bin');local.parent.mkdir(exist_ok=True)
 r=R.op(label+'-capture','phone','exec',argv=[client,mode,t]);s.setdefault('capture_receipts',{})[label]=r;persist()
 # The relay classifies a decoded diagnostic refusal (exit1) as error even
 # when the client has successfully flushed the complete raw result. Preserve
 # that captured failure rather than dropping it or repeating the operation.
 assert r['status']in('ok','error'),r
 try:v=json.loads(r['output'])
 except (ValueError,KeyError):raise AssertionError(r)
 assert v.get('captured')and v['mode']==mode and v['token']==t,v
 assert (v['ok']and r.get('exit_code',0)==0 and r['status']=='ok')or(not v['ok']and r.get('exit_code')==1 and r['status']=='error'),r
 get=R.op(label+'-retain','phone','get',path=remote,save=local);assert get['status']=='ok'and sha(local)==get['sha256']
 assert local.stat().st_size==v['bytes']
 command=[str(P/'inspect-record'),mode,str(local),str(P/'client-policy-01/native-G72-fixed50.bin'),t]
 q=subprocess.run(command,capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.stdout,q.stderr)
 d=json.loads(q.stdout);assert d['qualified']==v['ok']and d['bytes']==local.stat().st_size
 s.setdefault('records',{})[label]={'remote':remote,'local':str(local.relative_to(W)),'sha256':sha(local),'token':t,'decoded':d};persist()
 return d
def stage():
 qualify_build()
 s.setdefault('experiment',{'maximum_loads':1,'maximum_RUNs':1,'maximum_resource_writes':2,'resource_address':'0x40804','resource_data':0,'service':'OpenG35','device':'OpenG74','signed_sha256':signed,'client_sha256':clientsha,'physical_touch_required':False})
 assert s['experiment']['signed_sha256']==signed
 assert checked('hash-existing-loader','hash',path=loader)['sha256']==loadersha
 assert checked('hash-client','hash',path=client)['sha256']==clientsha
 a=execute('device-absent-before',[client,'absent',token('absence-before')]);assert a['device_absent']and not a['ioctls']
 a=execute('loader-service-absent-before',[loader,'absent']);assert a['device_absent']and a['service_absent']
 assert checked('put-small-signed-driver','put',file=P/'G74-signed.sys',path=driver)['sha256']==signed
 assert checked('hash-signed-driver','hash',path=driver)['sha256']==signed
 t=token('run');s['run_token']=t;persist()
 intent=json.dumps({'experiment':'G74-OFF-only-response-request-metadata','phone_session':R.sessions['phone'],'driver_sha256':signed,'client_sha256':clientsha,'run_token':t,'max_loads':1,'max_runs':1,'max_OFF_writes':2,'resource_data':0},sort_keys=True)
 payload=base64.b64encode(intent.encode()).decode();hostpath=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G74-native-once-'+t+'.json'
 ps="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$p='"+hostpath+"';$b=[Convert]::FromBase64String('"+payload+"');$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};@{ok=$true;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress"
 r=R.op('durable-host-once-intent','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(ps.encode('utf-16le')).decode()]);assert r['status']=='ok'and not r.get('exit_code',0),r
 lines=[x for x in r['output'].splitlines()if x.startswith('{')];assert len(lines)==1
 j=json.loads(lines[0]);assert j=={'ok':True,'sha256':hashlib.sha256(intent.encode()).hexdigest()}
 s['durable_host_intent']={'path':hostpath,'sha256':j['sha256']};persist('staged_verified_once_intent_created_no_driver_load')
def load():
 assert s['phase']=='staged_verified_once_intent_created_no_driver_load';qualify_build()
 s['load_result']=execute('load-exact-signed-driver-once',[loader,'load',driver,signed]);persist('driver_load_receipt_saved')
 assert s['load_result']['start_success']and s['load_result']['state']==4
 d=capture('status-before','status');assert d['qualified']and d['status']['map_calls']==d['status']['run_attempts']==d['status']['observer_captures']==0
 persist('native_load_and_zero_MMIO_status_verified')
def before():
 assert s['phase']=='native_load_and_zero_MMIO_status_verified'
 d=capture('snapshot-before','snapshot');assert d['qualified']
 d=capture('pmic-before','pmic');assert d['qualified']and d['attempt']==1 and d['status']['observer_captures']==1
 d=capture('ready-before','status');assert d['qualified']and d['ready']
 persist('native_exact_baseline_external_PMIC_off_ready_one_run')
def run():
 assert s['phase']=='native_exact_baseline_external_PMIC_off_ready_one_run';qualify_build()
 # No new token or job label may be used to retry this hardware operation.
 s['run_consumed_before_submission']=True;persist()
 d=capture('one-OFF-trial','run',s['run_token']);s['run_qualified']=d['qualified'];persist('one_native_OFF_trial_raw_saved_no_replay')
def after():
 assert s['phase']=='one_native_OFF_trial_raw_saved_no_replay'
 d=capture('pmic-after','pmic');s['post_pmic_qualified']=d['qualified']
 d=capture('snapshot-after','snapshot');s['post_snapshot_exact']=d['qualified']and d['values']==s['records']['snapshot-before']['decoded']['values'];persist()
 d=capture('status-after','status');s['post_status']=d;persist()
 capture('frozen-result','result',s['run_token']);s['cached_result_identical']=s['records']['frozen-result']['sha256']==s['records']['one-OFF-trial']['sha256'];assert s['cached_result_identical'];persist('native_post_evidence_saved_and_frozen_packet_identical')
def cleanup():
 assert 'load-exact-signed-driver-once'in s['jobs'],'Never unload an unrelated service'
 # Preserve failure/undo fields before removing the temporary code.
 # G35's source exposes the verb stop, which stops and deletes its own exact
 # hash-matching service; do not use its device-specific verbs with G74.
 s['unload_result']=execute('stop-delete-exact-installed-hash',[loader,'stop',signed]);persist()
 assert s['unload_result']['stopped']and s['unload_result']['delete_requested']
 a=execute('loader-service-absent-after',[loader,'absent']);assert a['device_absent']and a['service_absent']
 a=execute('G74-device-absent-after',[client,'absent',token('absence-after')]);assert a['device_absent']and not a['ioctls']
 a=execute('original-software-audit-after',[base+r'\G59-cleanup.exe','audit']);prior=json.loads((W/'pre-load.json').read_text())['audit_before'];assert a==prior
 s['audit_after']=a;persist('temporary_service_removed_original_software_exact_hardware_result_retained')
p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=['stage','load','before','run','after','cleanup']);a=p.parse_args();globals()[a.step]();print(json.dumps({'step':a.step,'phase':s['phase'],'run_qualified':s.get('run_qualified'),'post_pmic_qualified':s.get('post_pmic_qualified'),'cached_result_identical':s.get('cached_result_identical')}))
