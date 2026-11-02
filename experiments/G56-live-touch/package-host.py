"""Seal a root or uniquely matched child catalog with existing verified tools."""
from pathlib import Path
import argparse,datetime,hashlib,json,subprocess,sys
from relay import Relay
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--kind',choices=['root','child'],required=True);a=p.parse_args();subprocess.run([sys.executable,str(W/'preflight.py')],check=True,capture_output=True,text=True)
R=Relay('package-'+a.kind+'-host.json');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();root=a.kind=='root';base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G56-'+('package'if root else'vhf-package');tool=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-catalog-tools\Inf2Cat.exe';catalog='OpenG56.cat'if root else'G56Vhf.cat'
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
proof=json.loads((W.parent/'hid-G51/catalog-tool-signature.json').read_text())['verification'];assert proof['passed']and proof['same_bytes_from_pinned_official_WDK_package']
assert op('tool-hash','hash',path=tool)['sha256']==proof['tool_sha256']
clock=json.loads(op('host-clock','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"@{local_date=(Get-Date).ToString('yyyy-MM-dd');utc_date=[DateTime]::UtcNow.ToString('yyyy-MM-dd')}|ConvertTo-Json -Compress"])['output']);R.s['host_clock']=clock;R.persist()
inf=W/('OpenG56.inf'if root else'G56Vhf.inf');date=next(x.split('=',1)[1].split(',')[0]for x in inf.read_text().splitlines()if x.startswith('DriverVer='));assert datetime.datetime.strptime(date,'%m/%d/%Y').date()<=min(datetime.date.fromisoformat(v)for v in clock.values())
op('directory','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'Package directory already exists without this journal'};New-Item -ItemType Directory -Path $p|Out-Null"])
inputs=[(inf,inf.name),(W/'private/G56-public.cer','G56-public.cer')]
if root:inputs.insert(0,(W/'private/G56-signed.sys','OpenG56.sys'))
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
'''.replace('__CAT__',base+'\\'+catalog)
m=json.loads(op('sign-catalog','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps])['output']);assert m['CMS_signature_verified']and m['signer_thumbprint']==m['expected_thumbprint']=='0000000000000000000000000000000000000000';R.s['catalog_signature']=m;R.persist()
cat=W/'private'/catalog;r=op('get-catalog','get',path=base+'\\'+catalog,save=cat if not cat.exists()else None);assert sha(cat)==r['sha256']==m['sha256']
files={name:sha(local)for local,name in inputs};files[catalog]=sha(cat);manifest={'version':'G56-package-1'if root else'G56-vhf-package-1','files':files}
if root:manifest['interface_guid']=json.loads((W/'binding.json').read_text())['interface_guid']
else:manifest['base_manifest_sha256']=sha(W/'private/package.json')
out=W/'private'/('package.json'if root else'vhf-package.json');out.write_text(json.dumps(manifest,indent=2)+'\n');R.s.update(phase='catalog_signed_package_sealed_not_installed',manifest_sha256=sha(out));R.persist();print(json.dumps({'phase':R.s['phase'],'kind':a.kind,'manifest_sha256':sha(out),'files':files}))
