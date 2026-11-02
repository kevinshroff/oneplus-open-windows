"""Finish the pinned objects/package on the laptop only; no phone action."""
from pathlib import Path
import json,hashlib,re,zipfile
from ops import q,good,ps,observe,HOST
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
m=json.loads((p/'compile-final/compile.json').read_text());assert m['passed']
for n,h in m['source_sha256'].items():assert sha(w/'source'/n)==h,n
for n in ['driver-ASan-final','driver-TSan-final']:
 t=json.loads((p/n/'verification.json').read_text());assert t['passed']and t['actual_driver_cases']==81
 for f,h in t['source_sha256'].items():assert sha(w/f)==h,(n,f)
f=p/'G182-objects.zip'
with zipfile.ZipFile(f,'x',zipfile.ZIP_DEFLATED)as z:
 for o in m['objects']:assert sha(p/'compile-final'/o['object'])==o['sha256'];z.write(p/'compile-final'/o['object'],o['object'])
 z.write(w/'OpenG182.inf','OpenG182.inf')
text=(w.parent/'charging-G180/private/Finish-G180-Build.ps1').read_text().replace('G180','G182');lines=[x for x in text.splitlines()if 'object identity'not in x]
base='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\';folder=base+'G182-finished\\'
checks=["if((Get-FileHash -LiteralPath '"+folder+o['object']+"' -Algorithm SHA256).Hash.ToLowerInvariant() -ne '"+o['sha256']+"'){throw 'G182 object identity'}"for o in m['objects']];checks+=["if((Get-FileHash -LiteralPath '"+folder+"OpenG182.inf' -Algorithm SHA256).Hash.ToLowerInvariant() -ne '"+sha(w/'OpenG182.inf')+"'){throw 'INF identity'}"]
lines[4:4]=checks
for i,s in enumerate(lines):
 if s.startswith('& ')and "'/machine:arm64'"in s:
  s=re.sub(r" 'C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\G182-finished\\\w+\.obj'",'',s);at=s.index(" 'C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\G34-build")
  lines[i]=s[:at]+''.join(" '"+folder+o['object']+"'"for o in m['objects'])+s[at:]
text='\n'.join(lines[:-1])+'''\nCopy-Item -LiteralPath $signed -Destination (Join-Path $folder 'OpenG182.sys')
Export-Certificate -Cert $cert[0] -FilePath (Join-Path $folder 'G182-public.cer')|Out-Null
$catTool='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\G51-catalog-tools\\Inf2Cat.exe'
if((Get-FileHash -LiteralPath $catTool -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'b594728d38b271979367abc8060a971b8e42422738009be126710b1f5dd0fcbc'){throw 'Catalog tool identity'}
$catLog=(& $catTool ('/driver:'+$folder) /os:10_GE_ARM64 /verbose /uselocaltime 2>&1|Out-String)
if($LASTEXITCODE -ne 0){throw $catLog}
$cat=Join-Path $folder 'OpenG182.cat'
& $tool sign /fd SHA256 /s My /sha1 $cert[0].Thumbprint $cat|Out-Null
if($LASTEXITCODE -ne 0){throw 'Catalog sign failed'}
$catalogCms=New-Object Security.Cryptography.Pkcs.SignedCms;$catalogCms.Decode([IO.File]::ReadAllBytes($cat));$catalogCms.CheckSignature($true)
if($catalogCms.SignerInfos[0].Certificate.Thumbprint -ne $cert[0].Thumbprint){throw 'Catalog signer'}
$files=@{}
foreach($n in @('G182-unsigned.sys','OpenG182.sys','OpenG182.inf','OpenG182.cat','G182-public.cer')){$f=Join-Path $folder $n;$files[$n]=@{sha256=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $f).Length}}
@{phase='G182_link_signed_catalogued';cms_verified=$true;catalog_CMS_verified=$true;files=$files;catalog_result=$catLog;signer=$cert[0].Thumbprint;native_phone_operations=0}|ConvertTo-Json -Depth 6 -Compress
'''
(p/'Finish-G182-Build.ps1').write_text(text)
for n in ['G182-objects.zip','Finish-G182-Build.ps1']:good(q('put-'+n,'host','put',session=HOST,file=p/n,path=n,timeout=25))
r=good(q('link-sign','host',session=HOST,argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',base+'Finish-G182-Build.ps1'],timeout=90));v=json.loads(r['output']);assert v['cms_verified']and v['catalog_CMS_verified']
for n,h in v['files'].items():
 r=good(q('get-'+n,'host','get',session=HOST,path=folder+n,timeout=20));r=observe('get-'+n,save=p/n);assert sha(p/n)==h['sha256']
(p/'package-build.json').write_text(json.dumps(v,indent=2)+'\n');print({'phase':v['phase'],'files':v['files']})
