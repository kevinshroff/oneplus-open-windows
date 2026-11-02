"""VM-native append-only table change after verifying the independent backup."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys
assert sys.platform.startswith('linux');W=Path(__file__).resolve().parent;P=W/'private';S=W/'WIM-build-state.json';assert not S.exists();source=Path('/tmp/G23-gpio-input-v1.wim');target=Path('/tmp/G64-G63-resource-v1.wim');assert source.is_file()and not target.exists();backup=json.loads((W/'WIM-source-backup.json').read_text());assert backup['phase']=='Mac_retained_independent_source_backup_verified'
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
expected='bf8da75a5ff96af9c65fb5f059e6cbb8206595aeeee9c5057e31e31bd4e30250';assert sha(source)==sha(Path(backup['retained_source']))==backup['source_sha256']==expected and source.stat().st_size==backup['source_bytes']==592882167
v=os.statvfs('/tmp');free=v.f_frsize*v.f_bavail;assert free>16*1024*1024
B=W.parent/'resources-G63';table=B/'private/acpi-02/acpitabl.dat';assert sha(table)=='cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece';r={'phase':'independent_Mac_backup_and_VM_source_verified_before_temp_reuse','source_sha256':expected,'retained_source':backup['retained_source'],'target':str(target),'tmp_free_before':free,'commands':[],'changed_paths':['Windows/System32/acpitabl.dat'],'phone_operations':0}
def save():
 r['updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();p=S.with_suffix('.tmp');p.write_text(json.dumps(r,indent=2)+'\n');p.replace(S)
def run(phase,argv,data=None):
 r['phase']=phase;save();log=P/(phase+'.log')
 with log.open('xb')as f:q=subprocess.run(argv,input=data,stdout=f,stderr=subprocess.STDOUT)
 r['commands'].append({'phase':phase,'argv':argv,'exit_code':q.returncode,'log_sha256':sha(log)});save();assert q.returncode==0,str(log);print(phase,flush=True)
save();source.rename(target);run('verify-source-before',['wimlib-imagex','verify',str(target)]);command='add "'+str(table)+'" "/Windows/System32/acpitabl.dat"\n';(P/'WIM-update-command.txt').write_text(command);run('update-one-table',['wimlib-imagex','update',str(target),'1','--check'],command.encode());run('verify-target-after',['wimlib-imagex','verify',str(target)]);out=subprocess.check_output(['wimlib-imagex','extract',str(target),'1','Windows/System32/acpitabl.dat','--to-stdout']);assert out==table.read_bytes();r.update(phase='VM_native_G63_table_trial_verified_not_deployed',bytes=target.stat().st_size,sha256=sha(target));save();print(json.dumps({k:r[k]for k in['phase','bytes','sha256','changed_paths']}),flush=True)
