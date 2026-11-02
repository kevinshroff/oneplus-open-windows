"""Bounded read-only resource snapshot; one durable job, raw bytes then analysis."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,uuid
from relay import Relay
p=argparse.ArgumentParser();p.add_argument('--phase',choices=['stage','run','collect','audit-after'],required=True);a=p.parse_args();W=Path(__file__).resolve().parent;B=W.parent/'close-cancel-G61';J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();R=Relay('native-snapshot-v2.json');s=R.s;remote=r'X:\OpenG17\payloads\G62-resources-v2.exe';cleanup=r'X:\OpenG17\payloads\G59-cleanup.exe';m=J(W/'private/helper-02/build.json')
assert J(B/'native-qualification-idle-close.json')['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
assert J(B/'idle-close-audit.json')['passed']
assert sha(W/'private/helper-02/g62-resources-arm64.exe')==m['binary_sha256']
for name,h in m['source_files_sha256'].items():assert sha(W/name)==h
assert J(W/'private/codec-02/tests.json')['passed']and J(W/'private/codec-02/tests.json')['decoder_source_sha256']==sha(W/'resource.go')
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def native(label,argv,**kw):
 v=json.loads(op(label,'exec',argv=argv,**kw)['output']);assert v['ok'],v;return v['result']
if a.phase=='stage':
 assert not s.get('phase')
 s['audit_before']=native('audit-before',[cleanup,'audit']);v=s['audit_before'];prior=J(B/'native-qualification-idle-close.json')['audit_after'];assert v==prior
 assert op('put-query-helper','put',file=W/'private/helper-02/g62-resources-arm64.exe',path=remote)['sha256']==m['binary_sha256'];assert op('hash-query-helper','hash',path=remote)['sha256']==m['binary_sha256']
 s.update(phase='read_only_helper_staged_original_stack_verified',token=uuid.uuid4().hex,maximum_snapshot_invocations=1);R.persist()
elif a.phase=='run':
 assert s['phase']=='read_only_helper_staged_original_stack_verified'
 s['snapshot_summary']=native('single-read-only-snapshot',[remote,'capture',s['token']],timeout=45);s['phase']='single_read_only_snapshot_returned';R.persist()
elif a.phase=='collect':
 assert s['phase']=='single_read_only_snapshot_returned'
 path=W/'private/native-resources-v2.json';r=op('get-resource-snapshot','get',path=s['snapshot_summary']['path'],save=path if not path.exists()else None);assert sha(path)==r['sha256']==s['snapshot_summary']['sha256']
 d=J(path);assert d['version']=='G62-resource-snapshot2'and d['native_arch']=='arm64'and d['processors']==8 and d['DSDT_sha256']=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
 assert d['hardware_register_reads']==d['hardware_register_writes']==d['native_device_or_configuration_mutations']==0
 s['snapshot_sha256']=sha(path);s['phase']='raw_native_resource_snapshot_preserved';R.persist();print(json.dumps({'devices':len(d['devices']),'descriptors':d['descriptor_count'],'warnings':d['enumeration_warnings']}))
elif a.phase=='audit-after':
 assert s['phase']=='raw_native_resource_snapshot_preserved'
 s['audit_after']=native('audit-after',[cleanup,'audit']);assert s['audit_after']==s['audit_before'];s['probe_after']=op('probe-after','probe');assert s['probe_after']['detail']['cpus']==8 and s['probe_after']['detail']['arch']=='arm64'
 s['phase']='read_only_snapshot_preserved_original_stack_and_same_G17_control_verified';R.persist()
print(json.dumps({'phase':s.get('phase'),'summary':s.get('snapshot_summary')}))
