"""Build and sign a sealed G51 PnP package using the pinned Microsoft SDK tools."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('package-host.json');base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-package';tool=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-catalog-tools\Inf2Cat.exe';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=json.loads((W/'signature-verification.json').read_text());signed=W/'private/G51-signed.sys';assert sha(signed)==proof['signed_driver_sha256'];assert json.loads((W/'catalog-tool-signature.json').read_text())['verification']['passed']
for p in [W/'private/driver-model-01/tests.json',W/'private/report-model-01/tests.json',W/'private/ABI-model-02/tests.json']:assert json.loads(p.read_text())['passed']
r=R.op('directory','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'Package directory exists without recorded intent'};New-Item -ItemType Directory -Path $p|Out-Null"]);assert r['status']=='ok'
for local,name in [(signed,'OpenG51.sys'),(W/'OpenG51.inf','OpenG51.inf'),(W/'private/G51-public.cer','G51-public.cer')]:
 remote=base+'\\'+name;assert R.op('put-'+name,'host','put',file=local,path=remote)['sha256']==sha(local);assert R.op('hash-'+name,'host','hash',path=remote)['sha256']==sha(local)
r=R.op('create-catalog','host','exec',argv=[tool,'/driver:'+base,'/os:10_GE_ARM64','/verbose','/uselocaltime']);R.s['catalog_creation']=r;R.persist();assert r['status']=='ok'and r.get('exit_code')==0,r
ps=r'''
$ErrorActionPreference='Stop';$cat='__CAT__';$tool='C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe';$c=@(Get-ChildItem Cert:\CurrentUser\My|Where-Object {$_.Subject -eq 'CN=OnePlusOpen G34 Private Lab 20261021'});if($c.Count -ne 1){throw 'Expected existing project certificate'}
$log=(& $tool sign /fd SHA256 /s My /sha1 $c[0].Thumbprint /v $cat 2>&1|Out-String);if($LASTEXITCODE -ne 0){throw $log};Add-Type -AssemblyName System.Security;$cms=New-Object Security.Cryptography.Pkcs.SignedCms;$cms.Decode([IO.File]::ReadAllBytes($cat));$cms.CheckSignature($true);$a=Get-AuthenticodeSignature -LiteralPath $cat
@{CMS_signature_verified=$true;signer_thumbprint=$cms.SignerInfos[0].Certificate.Thumbprint;expected_thumbprint=$c[0].Thumbprint;sha256=(Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash.ToLower();Windows_trust_status=[string]$a.Status;Windows_trust_message=$a.StatusMessage;root_store_changed=$false;private_key_exported=$false}|ConvertTo-Json -Compress
'''.replace('__CAT__',base+r'\OpenG51.cat')
r=R.op('sign-catalog','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps]);assert r['status']=='ok'and r.get('exit_code')==0,r;m=json.loads(r['output']);assert m['CMS_signature_verified']and m['signer_thumbprint']==m['expected_thumbprint']=='0000000000000000000000000000000000000000';R.s['catalog_signature']=m;R.persist()
p=W/'private/OpenG51.cat';r=R.op('get-catalog','host','get',path=base+r'\OpenG51.cat',save=p if not p.exists()else None);assert r['status']=='ok'and sha(p)==r['sha256']==m['sha256']
manifest={'version':'G51-package-1','interface_guid':json.loads((W/'binding.json').read_text())['interface_guid'],'files':{'OpenG51.sys':sha(signed),'OpenG51.inf':sha(W/'OpenG51.inf'),'OpenG51.cat':sha(p),'G51-public.cer':sha(W/'private/G51-public.cer')}};(W/'private/package.json').write_text(json.dumps(manifest,indent=2)+'\n');R.s['phase']='catalog_signed_package_sealed_not_installed';R.s['manifest_sha256']=sha(W/'private/package.json');R.persist();print(json.dumps({'phase':R.s['phase'],'manifest_sha256':R.s['manifest_sha256'],'files':manifest['files']}))
