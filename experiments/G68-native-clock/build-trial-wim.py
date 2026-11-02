"""Linux VM append-only WIM update, independently retained source; no phone I/O."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys

assert sys.platform.startswith('linux')
W=Path(__file__).resolve().parent;P=W/'private';S=W/'WIM-build-state.json'
source=W.parent/'ram-handoff-G64/private/G64-G63-resource-v1.wim'
table=W.parent/'clock-owner-G67/private/acpi-02/acpitabl.dat'
target=Path('/tmp/G68-G67-resource-v1.wim')
assert not S.exists() and not target.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8<<20),b''):h.update(b)
 return h.hexdigest()
assert source.stat().st_size==594423099 and sha(source)=='cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7'
assert table.stat().st_size==742 and sha(table)=='1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1'
st=os.statvfs('/tmp');assert st.f_bavail*st.f_frsize>source.stat().st_size+64*1024*1024
r={'phase':'retained_source_verified_before_copy','source':str(source),'source_bytes':source.stat().st_size,'source_sha256':sha(source),'target':str(target),'changed_paths':['Windows/System32/acpitabl.dat'],'commands':[],'phone_operations':0}
def save():S.write_text(json.dumps(r,indent=2)+'\n')
def run(phase,argv,data=None):
 r['phase']=phase;save();log=P/(phase+'.log')
 with log.open('xb')as f:q=subprocess.run(argv,input=data,stdout=f,stderr=subprocess.STDOUT)
 r['commands'].append({'phase':phase,'argv':argv,'exit_code':q.returncode,'log_sha256':sha(log)});save()
 assert q.returncode==0,str(log)
 print(phase,flush=True)
save()
with source.open('rb')as f,target.open('xb')as g:
 shutil.copyfileobj(f,g,8<<20);g.flush();os.fsync(g.fileno())
assert sha(target)==r['source_sha256']
run('verify-source-before',['wimlib-imagex','verify',str(target)])
command='add "'+str(table)+'" "/Windows/System32/acpitabl.dat"\n'
(P/'WIM-update-command.txt').write_text(command)
run('update-one-table',['wimlib-imagex','update',str(target),'1','--check'],command.encode())
run('verify-target-after',['wimlib-imagex','verify',str(target)])
assert subprocess.check_output(['wimlib-imagex','extract',str(target),'1','Windows/System32/acpitabl.dat','--to-stdout'])==table.read_bytes()
assert sha(source)==r['source_sha256']
r.update(phase='VM_native_G67_table_trial_verified_not_deployed',bytes=target.stat().st_size,sha256=sha(target));save()
dest=P/target.name;assert not dest.exists()
with target.open('rb')as f,dest.open('xb')as g:
 shutil.copyfileobj(f,g,8<<20);g.flush();os.fsync(g.fileno())
assert dest.stat().st_size==r['bytes'] and sha(dest)==r['sha256']
r.update(phase='Mac_retained_trial_copy_matches_VM_full_hash',retained_target=str(dest));save()
print(json.dumps({k:r[k]for k in ['phase','bytes','sha256']}),flush=True)
