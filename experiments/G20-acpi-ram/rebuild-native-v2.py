"""Rebuild only a separate trial WIM, verifying actual compressed resources at each stage."""
from pathlib import Path
import hashlib,json,subprocess,datetime
W=Path('/path/to/user/Documents/Codex/2026-10-20/sta/work/maintenance-G18/acpi-G20')
P=W/'private';state=W/'build-native-v2-state.json';assert not state.exists()
source=W.parent/'private/G18-maintenance.wim';target=Path('/tmp/G20-canary-native-v2.wim')
assert not target.exists()
s={'phase':'validate_original','source_sha256_expected':'1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9','target':str(target),'commands':[]}
def save():
 s['updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();q=state.with_suffix('.tmp');q.write_text(json.dumps(s,indent=2)+'\n');q.replace(state)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(phase,args):
 s['phase']=phase;log=P/(phase+'.log');assert not log.exists();save();print(phase,flush=True)
 with log.open('xb') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 s['commands'].append({'phase':phase,'argv':args,'exit_code':r.returncode,'log':str(log),'log_sha256':digest(log)});save()
 if r.returncode:print(log.read_text(errors='replace')[-1400:].replace('\r','\n'),flush=True);raise SystemExit(r.returncode)
save();assert digest(source)==s['source_sha256_expected']
run('verify-original-before-v2',['wimlib-imagex','verify',str(source)])
bad=Path('/tmp/G20-canary-LZX-d230cc39.wim')
if bad.exists():
 assert digest(bad)=='d230cc390e895d644a80dd97634e9f16af93accdd49db6057805763af8136acf';assert digest(P/'G20-canary-LZX.wim')==digest(bad);bad.unlink()
run('export-native-v2',['wimlib-imagex','export',str(source),'1',str(target),'--compress=LZX:100','--boot','--check','--threads=2'])
s['export_sha256']=digest(target);save()
run('verify-native-v2-before-update',['wimlib-imagex','verify',str(target)])
commands='add "'+str(P/'acpitabl.dat')+'" /Windows/System32/acpitabl.dat\n'
cmd=P/'canary-native-v2-update.txt';assert not cmd.exists();cmd.write_text(commands)
run('update-native-v2',['wimlib-imagex','update',str(target),'1','--check','--command='+commands.strip()])
run('verify-native-v2-after-update',['wimlib-imagex','verify',str(target)])
s['phase']='native_v2_fully_verified';s['final_sha256']=digest(target);s['final_bytes']=target.stat().st_size;save();print(json.dumps({k:s[k] for k in ['phase','final_sha256','final_bytes']}),flush=True)
