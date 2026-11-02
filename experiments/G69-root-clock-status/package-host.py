"""Create/sign only the G69 package with the existing qualified host tooling."""
from pathlib import Path
import datetime,hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;subprocess.run([sys.executable,str(W/'preflight.py')],capture_output=True,text=True,check=True);R=Relay('package-host.json');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G69-package-01';tool=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-catalog-tools\Inf2Cat.exe'
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
proof=json.loads((W.parent/'hid-G51/catalog-tool-signature.json').read_text())['verification'];assert proof['passed']and proof['same_bytes_from_pinned_official_WDK_package'];assert op('tool-hash','hash',path=tool)['sha256']==proof['tool_sha256']
clock=json.loads(op('host-clock','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"@{local_date=(Get-Date).ToString('yyyy-MM-dd');utc_date=[DateTime]::UtcNow.ToString('yyyy-MM-dd')}|ConvertTo-Json -Compress"])['output']);assert datetime.date(2026,10,21)<=min(datetime.date.fromisoformat(v)for v in clock.values());R.s['host_clock']=clock;R.persist()
op('directory','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'G69 package already exists without this recorded job'};New-Item -ItemType Directory -Path $p|Out-Null"])
inputs=[(W/'private/G69-signed.sys','OpenG69.sys'),(W/'OpenG69.inf','OpenG69.inf'),(W/'private/G69-public.cer','G69-public.cer')]
for local,name in inputs:
 remote=base+'\\'+name;assert op('put-'+name,'put',file=local,path=remote)['sha256']==sha(local);assert op('hash-'+name,'hash',path=remote)['sha256']==sha(local)
R.s['catalog_creation']=op('create-catalog','exec',argv=[tool,'/driver:'+base,'/os:10_GE_ARM64','/verbose','/uselocaltime']);R.persist()
ps=r'''
$ErrorActionPreference='Stop';$cat='__CAT__';$tool='C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
if((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid'){throw 'SDK signing tool verification failed'}
$c=@(Get-ChildItem Cert:\CurrentUser\My|Where-Object {$_.Subject -eq 'CN=OnePlusOpen G34 Private Lab 20261021'});if($c.Count -ne 1){throw 'Expected existing project certificate'}
$log=(& $tool sign /fd SHA256 /s My /sha1 $c[0].Thumbprint /v $cat 2>&1|Out-String);if($LASTEXITCODE -ne 0){throw $log}
Add-Type -AssemblyName System.Security;$cms=New-Object Security.Cryptography.Pkcs.SignedCms;$cms.Decode([IO.File]::ReadAllBytes($cat));$cms.CheckSignature($true);$a=Get-AuthenticodeSignature -LiteralPath $cat
@{CMS_signature_verified=$true;signer_thumbprint=$cms.SignerInfos[0].Certificate.Thumbprint;expected_thumbprint=$c[0].Thumbprint;sha256=(Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash.ToLower();Windows_trust_status=[string]$a.Status;Windows_trust_message=$a.StatusMessage;root_store_changed=$false;private_key_exported=$false}|ConvertTo-Json -Compress
'''.replace('__CAT__',base+r'\OpenG69.cat')
m=json.loads(op('sign-catalog','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps])['output']);assert m['CMS_signature_verified']and m['signer_thumbprint']==m['expected_thumbprint']=='0000000000000000000000000000000000000000';R.s['catalog_signature']=m;R.persist();cat=W/'private/OpenG69.cat';r=op('get-catalog','get',path=base+r'\OpenG69.cat',save=cat if not cat.exists()else None);assert sha(cat)==r['sha256']==m['sha256']
files={name:sha(local)for local,name in inputs};files['OpenG69.cat']=sha(cat);manifest={'version':'G69-package-1','files':files,'interface_guid':'2f1df03e-a4ab-4e14-a587-32af76b23969','hardware_id':'ACPI\\OPEN0067','trial_DSDT_sha256':'1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1'};out=W/'private/package.json';out.write_text(json.dumps(manifest,indent=2)+'\n');R.s.update(phase='catalog_signed_package_sealed_not_installed',manifest_sha256=sha(out));R.persist();print(json.dumps({'phase':R.s['phase'],'manifest_sha256':sha(out),'files':files}))
