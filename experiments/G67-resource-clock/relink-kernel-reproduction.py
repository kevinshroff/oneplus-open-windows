"""Relink hash-equal clean-build objects in a new host directory."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('kernel-relink-reproduction.json');s=R.s
proof=json.loads((P/'kernel-reproduction-01/source-reproduction.json').read_text());old=json.loads((W/'link.json').read_text());assert proof['passed']and proof['ARM64_objects_byte_identical']
source=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G67-clock-build-01';dest=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G67-clock-reproduction-01'
rows=[]
for row in proof['objects']:rows.append({'source':source+'\\'+row['object'],'destination':dest+'\\'+row['object'],'sha256':row['sha256']})
for row in old['libraries']:rows.append({'source':row['path'],'destination':None,'sha256':row['sha256']})
argv=[a.replace(source,dest)for a in old['link_argv']];assert argv[0].endswith('link.exe')and any(a.startswith('/out:')for a in argv)
q=lambda v:json.dumps(v).replace("'","''")
ps=r'''
$ErrorActionPreference='Stop'
$g67Dest='__DEST__';if(Test-Path -LiteralPath $g67Dest){throw 'Preserve existing reproduced kernel build'}
$g67Rows=ConvertFrom-Json '__ROWS__';$g67Args=ConvertFrom-Json '__ARGV__';$g67Link=$g67Args[0];$g67Args=@($g67Args|Select-Object -Skip 1)
if((Get-FileHash -LiteralPath $g67Link -Algorithm SHA256).Hash.ToLower() -ne '7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762'){throw 'Linker differs'}
foreach($g67Row in $g67Rows){if((Get-FileHash -LiteralPath $g67Row.source -Algorithm SHA256).Hash.ToLower() -ne $g67Row.sha256){throw 'Input differs'}}
New-Item -ItemType Directory -Path $g67Dest|Out-Null
foreach($g67Row in $g67Rows){if($g67Row.destination){Copy-Item -LiteralPath $g67Row.source -Destination $g67Row.destination;if((Get-FileHash -LiteralPath $g67Row.destination -Algorithm SHA256).Hash.ToLower() -ne $g67Row.sha256){throw 'Copied input differs'}}}
$g67Log=(& $g67Link @g67Args 2>&1|Out-String);if($LASTEXITCODE -ne 0){throw $g67Log}
$g67Output=Join-Path $g67Dest 'G67-unsigned.sys';$g67SHA=(Get-FileHash -LiteralPath $g67Output -Algorithm SHA256).Hash.ToLower()
@{sha256=$g67SHA;bytes=(Get-Item -LiteralPath $g67Output).Length;input_hashes_verified=$true;clean_objects_equal_to_copied_inputs=$true;native_hardware_operations=0}|ConvertTo-Json -Compress
'''.replace('__DEST__',dest).replace('__ROWS__',q(rows)).replace('__ARGV__',q(argv))
script=P/'relink-reproduction.ps1'
if script.exists():assert script.read_text()==ps
else:script.write_text(ps)
r=R.op('stage-reproduction-script','host','put',file=script,path='G67-relink-reproduction.ps1');assert r['status']=='ok'and r['sha256']==hashlib.sha256(script.read_bytes()).hexdigest()
r=R.op('single-reproduced-kernel-link','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G67-relink-reproduction.ps1']);assert r['status']=='ok';result=json.loads(r['output']);s['result']=result;R.persist();assert result['sha256']==old['output_sha256']
s.update(phase='unsigned_kernel_PE_reproduced_byte_identically_from_hash_equal_clean_build_inputs',source_reproduction_sha256=hashlib.sha256((P/'kernel-reproduction-01/source-reproduction.json').read_bytes()).hexdigest(),unsigned_sha256=result['sha256'],native_clock_operation_qualified=False);R.persist();print(json.dumps({k:s[k]for k in ['phase','unsigned_sha256']}))
