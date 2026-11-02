"""Stage the pinned Microsoft catalog tools on the existing Windows build host."""
from pathlib import Path
import json,hashlib
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('catalog-tools-host.json');base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-catalog-tools';D=W/'private/catalog-tools';meta=json.loads((D/'extraction.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=R.op('directory','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'Catalog tool directory exists without this intent'};New-Item -ItemType Directory -Path $p|Out-Null"]);assert r['status']=='ok'
for row in meta['files']:
 p=D/row['file'];assert sha(p)==row['sha256'];dest=base+'\\'+p.name
 assert R.op('put-'+p.name,'host','put',file=p,path=dest)['sha256']==sha(p)
 assert R.op('hash-'+p.name,'host','hash',path=dest)['sha256']==sha(p)
ps="$ErrorActionPreference='Stop';$p='"+base+"\\Inf2Cat.exe';$s=Get-AuthenticodeSignature -LiteralPath $p;@{status=[string]$s.Status;subject=$s.SignerCertificate.Subject;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress"
r=R.op('publisher','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps]);assert r['status']=='ok';v=json.loads(r['output']);R.s['publisher']=v;R.persist();assert'Microsoft'in v['subject']
if v['status']!='Valid':
 proof=json.loads((W/'catalog-tool-signature.json').read_text())['verification'];assert proof['passed']and proof['tool_sha256']==v['sha256']and proof['CMS_signature_and_Authenticode_SHA256_digest_verified']and proof['same_bytes_from_pinned_official_WDK_package']and'not trusted'in proof['Windows_trust_message']
r=R.op('help','host','exec',argv=[base+r'\Inf2Cat.exe','/?']);assert r['status']=='ok'and r.get('exit_code')==0,r;R.s['help']=r['output'];R.persist();print(r['output'][-6000:])
