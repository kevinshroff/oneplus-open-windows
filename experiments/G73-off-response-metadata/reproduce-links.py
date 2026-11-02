"""Relink pinned existing inputs after clean-source COFF reproduction.

This only uses the build laptop. No phone jobs or test-signing operations.
"""
from pathlib import Path
import base64,hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('reproduce-links.json');s=R.s
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((P/'reproduce-01/reproduction.json').read_text());assert proof['passed']and proof['all_object_hashes_match']
driver=json.loads((W/'link-02.json').read_text());client=json.loads((W/'client-link.json').read_text())
assert driver['phase']=='unsigned_native_ARM64_driver_linked_not_loaded'
assert client['phase']=='small_native_ARM64_client_linked_not_executed'
files=[];builds=[]
for old,kind,outname in [(driver,'driver','G73-unsigned.sys'),(client,'client','G73-client.exe')]:
 argv=old['link_argv'];base=next(x[5:].rsplit('\\',1)[0]for x in argv if x.lower().startswith('/out:'))
 for row in (json.loads((P/('compile-04'if kind=='driver'else'client-objects-03')/'compile.json').read_text())['objects']):files.append({'path':base+'\\'+row['object'],'sha256':row['sha256']})
 if kind=='driver':files+=old['libraries']
 else:files += [{'path':base+'\\'+x['name'],'sha256':x['sha256']}for x in old['inputs']if x['name'].lower().endswith('.lib')]
 args=[('/out:'+base+'\\reproduced-'+outname)if x.lower().startswith('/out:')else('/map:'+base+'\\reproduced-'+outname+'.map')if x.lower().startswith('/map:')else x for x in argv[1:]]
 builds.append({'linker':argv[0],'args':args,'path':base+'\\reproduced-'+outname,'sha256':old['sha256']if kind=='driver'else old['binary_sha256']})
files.append({'path':driver['link_argv'][0],'sha256':'7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762'})
payload=base64.b64encode(json.dumps({'files':files,'builds':builds}).encode()).decode()
ps="""$ErrorActionPreference='Stop'
$j=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PAYLOAD'))|ConvertFrom-Json
foreach($f in $j.files){if((Get-FileHash -Algorithm SHA256 -LiteralPath $f.path).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Reproduction input hash mismatch'}}
$results=@()
foreach($b in $j.builds){
 if(Test-Path -LiteralPath $b.path){throw 'Preserve existing reproduction output'}
 $linker=$b.linker;$arguments=@($b.args);& $linker @arguments | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Reproduction linker failed'}
 $hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $b.path).Hash.ToLowerInvariant()
 if($hash -cne $b.sha256){throw ('Reproduction binary mismatch '+$hash)}
 $results+=@{path=$b.path;sha256=$hash}
}
@{ok=$true;input_count=$j.files.Count;outputs=$results}|ConvertTo-Json -Depth 5 -Compress
""".replace('PAYLOAD',payload)
s.setdefault('input_contract',files);s['full_input_contract']=files;s['builds']=builds;R.persist()
r=R.op('relink-on-build-host','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(ps.encode('utf-16le')).decode()]);assert r['status']=='ok'and not r.get('exit_code',0),r
lines=[x for x in r['output'].splitlines()if x.startswith('{')];assert len(lines)==1,r
v=json.loads(lines[0]);assert v['ok']and len(v['outputs'])==2
# The first captured PowerShell process also emitted a benign CLIXML progress
# stream. Observe its saved JSON without relinking. Recheck every library,
# including case-insensitive SDK .Lib names, plus both exact output hashes.
contract=base64.b64encode(json.dumps(files+[{'path':b['path'],'sha256':b['sha256']}for b in builds]).encode()).decode()
check="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$j=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+contract+"'))|ConvertFrom-Json;foreach($f in $j){if((Get-FileHash -Algorithm SHA256 -LiteralPath $f.path).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Full reproduction contract mismatch'}};@{ok=$true;verified=$j.Count}|ConvertTo-Json -Compress"
r=R.op('verify-full-input-and-output-contract','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(check.encode('utf-16le')).decode()]);assert r['status']=='ok'and not r.get('exit_code',0),r
lines=[x for x in r['output'].splitlines()if x.startswith('{')];assert len(lines)==1
full=json.loads(lines[0]);assert full=={'ok':True,'verified':len(files)+2}
s['full_input_and_output_verification']=full
for b in builds:
 out=P/'reproduce-01'/Path(b['path'].replace('\\','/')).name
 r=R.op('retain-'+out.name,'host','get',path=b['path'],save=out)
 assert r['status']=='ok'and sha(out)==b['sha256']
s.update(phase='clean_source_objects_and_both_executables_reproduced_byte_identically',result=v,native_phone_operations=0);R.persist();print(json.dumps({k:s[k]for k in ['phase','result','native_phone_operations']}))
