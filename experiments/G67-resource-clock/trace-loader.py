"""One image-specific loader trace with exact preflight and explicit cleanup."""
from pathlib import Path
import json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('loader-trace.json');s=R.s
key=r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\G67-client-v3.exe';reg=r'X:\Windows\System32\reg.exe';exe=r'X:\OpenG17\payloads\G67-client-v3.exe'
old=json.loads((W/'loader-investigation.json').read_text())['jobs']['check-project-IFEO-absent']['receipt'];assert old['status']=='error'and old['exit_code']==1
def phone(label,*args,allow=False):
 r=R.op(label,'phone','exec',argv=list(args));
 if not allow:assert r['status']=='ok'and r.get('exit_code',0)==0,r
 return r
proof=R.op('live-signed-debugger-and-log','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$e=@(Get-NetUDPEndpoint -LocalPort 50000);if($e.Count -ne 1 -or $e[0].OwningProcess -ne 15412){throw 'Debugger identity changed'};$p=Get-Process -Id 15412;if($p.ProcessName -ne 'EngHost'){throw 'Wrong engine'};$a=Get-AuthenticodeSignature -LiteralPath $p.Path;if($a.Status -ne 'Valid' -or $a.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Publisher differs'};$log='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\logs\\G66-lifecycle-01\\windbg.txt';@{engine=$p.Id;log_bytes=(Get-Item -LiteralPath $log).Length;publisher=$a.SignerCertificate.Subject}|ConvertTo-Json -Compress"]);assert proof['status']=='ok';s['debugger_before']=json.loads(proof['output']);R.persist()
fresh=phone('fresh-project-key-absent',reg,'query',key,allow=True);assert fresh['status']=='error'and fresh['exit_code']==1
phone('add-project-loader-snaps',reg,'add',key,'/v','GlobalFlag','/t','REG_SZ','/d','0x00000002','/f')
try:
 q=phone('verify-only-project-loader-snaps',reg,'query',key);assert q['output'].count('REG_SZ')==1 and '0x00000002'in q['output']
 if'nonce'not in s:s['nonce']=uuid.uuid4().hex;R.persist()
 result=phone('single-client-startup-with-loader-snaps',exe,'query',s['nonce'],allow=True);s['startup_response']=result;R.persist()
finally:
 q=phone('pre-cleanup-exact-project-value',reg,'query',key);assert q['output'].count('REG_SZ')==1 and '0x00000002'in q['output']
 phone('remove-owned-project-loader-snaps-key',reg,'delete',key,'/f')
 q=phone('verify-project-key-absent-after-cleanup',reg,'query',key,allow=True);assert q['status']=='error'and q['exit_code']==1;s['project_IFEO_key_removed']=True;R.persist()
ps="""$ErrorActionPreference='Stop';$p='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\logs\\G66-lifecycle-01\\windbg.txt';$f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$offset=__OFFSET__;$f.Seek($offset,[IO.SeekOrigin]::Begin)|Out-Null;$r=New-Object IO.StreamReader($f);$text=$r.ReadToEnd();if($text.Length -gt 262144){throw 'Trace exceeds bounded copy'};$out='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\G67-loader-trace.txt';if(Test-Path -LiteralPath $out){throw 'Preserve earlier trace'};[IO.File]::WriteAllText($out,$text);@{bytes=(Get-Item -LiteralPath $out).Length;sha256=(Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower();lines=($text -split [Environment]::NewLine).Length}|ConvertTo-Json -Compress}finally{$f.Dispose()}""".replace('__OFFSET__',str(s['debugger_before']['log_bytes']))
r=R.op('copy-bounded-new-loader-output','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps]);assert r['status']=='ok';s['trace_metadata']=json.loads(r['output']);R.persist()
r=R.op('retain-loader-trace','host','get',path=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G67-loader-trace.txt',save=P/'G67-loader-trace.txt');assert r['status']=='ok'
s['phase']='project_loader_trace_retained_and_exact_IFEO_key_removed';R.persist();print(json.dumps({'phase':s['phase'],'metadata':s['trace_metadata']}))
