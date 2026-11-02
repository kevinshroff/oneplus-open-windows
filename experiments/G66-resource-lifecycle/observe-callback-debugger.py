"""Observe the already-launched engine; require full code match before any CM change."""
from pathlib import Path
import hashlib,json,re,sqlite3,time
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';b=json.loads((W/'boot-resource.json').read_text());launch=json.loads((W/'callback-debugger-launch.json').read_text());assert launch['phase']=='single_callback_debugger_launch_acknowledged'
R=Relay('callback-debugger-observation.json',phone_session=b['session']);s=R.s
attempt=int(s.get('observations',0))+1;s['observations']=attempt;R.persist()
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
run=launch['launch']['run'];ps="$ErrorActionPreference='Stop';$e=@(Get-NetUDPEndpoint -LocalPort 50000);if($e.Count -ne 1){throw 'Need one current listener'};$p=Get-Process -Id $e[0].OwningProcess;$sig=Get-AuthenticodeSignature -LiteralPath $p.Path;if($p.ProcessName -ne 'EngHost' -or $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Current debugger identity differs'};$r='"+run+"';@{PID=$p.Id;publisher=$sig.SignerCertificate.Subject;log_exists=(Test-Path -LiteralPath ($r+'\\windbg.txt'));code_exists=(Test-Path -LiteralPath ($r+'\\native-code.bin'))}|ConvertTo-Json -Compress"
v=json.loads(op('engine-meta-'+str(attempt),'exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps])['output']);s['engine']=v;R.persist()
log=P/('callback-debugger-observation-%02d.txt'%attempt)
if v['log_exists']:op('retain-log-'+str(attempt),'get',path=run+r'\windbg.txt',save=log)
data=log.read_bytes();text=data.decode('utf-16')if data.startswith((b'\xff\xfe',b'\xfe\xff'))else data.decode('utf-8','replace')
code=P/'native-code.bin'
if v['code_exists']:op('retain-unpatched-native-code','get',path=run+r'\native-code.bin',save=code)
else:
 lines=text.splitlines();begins=[i for i,l in enumerate(lines)if l.strip()=='G66_NATIVE_CODE_BEGIN']
 if not begins:
  print(json.dumps({'phase':'existing_engine_observed_waiting_for_code_capture','engine':v}),flush=True);raise SystemExit(2)
 start=begins[-1];ends=[i for i,l in enumerate(lines)if i>start and l.strip()=='G66_NATIVE_CODE_END'];assert ends,'Observe the same running capture until complete'
 raw=bytearray();base=None
 for line in lines[start+1:ends[0]]:
  m=re.match(r'^\s*([0-9a-fA-F`]+)\s+(.+)$',line)
  if not m:continue
  address=int(m[1].replace('`',''),16);values=m[2].replace('-',' ').split()[:16]
  assert len(values)==16 and all(re.fullmatch('[0-9a-fA-F]{2}',x)for x in values),'Incomplete native code row'
  if base is None:base=address
  assert address==base+len(raw),'Noncontiguous native code dump'
  raw.extend(bytes.fromhex(''.join(values)))
 assert len(raw)==1424 and bytes(raw)==(P/'expected-native-code.bin').read_bytes(),'Native executing image differs; do not disable'
 if code.exists():assert code.read_bytes()==bytes(raw)
 else:code.write_bytes(raw)
 s['native_code_capture']='inline debugger byte dump before breakpoint installation';R.persist()
assert code.read_bytes()==(P/'expected-native-code.bin').read_bytes(),'Native executing image differs; do not disable'
assert 'G66_ARMED'in text.splitlines() and 'G66_REFUSED_CODE_MISMATCH'not in text.splitlines(),'Inspect script outcome before CM calls'
assert text.count('bu0 ')>=1 and all(('bu'+str(i)+' ')in text for i in range(5)),'Require all five deferred callbacks'
with sqlite3.connect(W.parent.parent/'control-G17/private/queue.sqlite3')as d:
 sid,seen=d.execute("select session,seen from nodes where node='phone'").fetchone()
assert sid==b['session']and time.time()-seen<15,'Wait for the same target to resume; do not replay debugger launch'
s.update(phase='native_code_matched_deferred_callbacks_armed_target_resumed',session=sid,native_code_bytes=code.stat().st_size,native_code_sha256=hashlib.sha256(code.read_bytes()).hexdigest(),five_deferred_probes_verified=True,native_CM_mutation_calls=0)
R.persist();print(json.dumps({k:s[k]for k in ['phase','session','native_code_bytes','native_code_sha256']}),flush=True)
