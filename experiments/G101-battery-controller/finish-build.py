from pathlib import Path
import json,hashlib,zipfile,sys
w=Path(__file__).resolve().parent
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=json.loads((w/'private/compile-04/compile.json').read_text())
for r in c['objects']:assert h(w/r['source'])==r['source_sha256'] and h(w/'private/compile-04'/r['object'])==r['sha256']
with zipfile.ZipFile(w/'private/G101-objects.zip','w',zipfile.ZIP_DEFLATED) as z:
 for r in c['objects']:z.write(w/'private/compile-04'/r['object'],r['object'])
libs=json.loads((w.parents[1]/'maintenance-G18/off-completion-G74/link-01.json').read_text())['libraries']
base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads'
folder=base+r'\G101-hubread-finished'
checks=[]
for r in c['objects']:checks.append((folder+'\\'+r['object'],r['sha256']))
checks.extend((r['path'],r['sha256']) for r in libs)
checks.append((r'C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe','7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762'))
ps="$ErrorActionPreference='Stop'\n$folder='"+folder+"'\nif(Test-Path -LiteralPath $folder){throw 'Build folder already exists; inspect existing result'}\nExpand-Archive -LiteralPath '"+base+"\\G101-objects.zip' -DestinationPath $folder\n"
for p,sha in checks:ps+="if((Get-FileHash -LiteralPath '"+p+"' -Algorithm SHA256).Hash.ToLowerInvariant() -ne '"+sha+"'){throw 'Build input hash'}\n"
link=checks[-1][0]
paths=[folder+'\\'+r['object'] for r in c['objects']]+[r['path'] for r in libs]
args=['/machine:arm64','/driver','/entry:FxDriverEntry','/subsystem:native,10.00','/osversion:10.0','/nodefaultlib','/dynamicbase','/nxcompat','/opt:ref','/opt:icf','/Brepro','/incremental:no','/out:'+folder+r'\G101-unsigned.sys']+paths
ps+="& '"+link+"' "+' '.join("'"+a+"'" for a in args)+" | Out-Null\nif($LASTEXITCODE -ne 0){throw 'Link failed'}\n"
ps+=r'''
$tool='C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
if((Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant() -ne '615b7d7a5156e53e8c500429912ff2b22eff3dc179db5e8f5c1fe4a5104804a5'){throw 'SDK signing tool hash'}
$cert=@(Get-ChildItem Cert:\CurrentUser\My|Where-Object{$_.Thumbprint -eq '0000000000000000000000000000000000000000'})
if($cert.Count -ne 1 -or -not $cert[0].HasPrivateKey){throw 'Existing project certificate required'}
$unsigned=Join-Path $folder 'G101-unsigned.sys';$signed=Join-Path $folder 'G101-signed.sys'
Copy-Item -LiteralPath $unsigned -Destination $signed
& $tool sign /fd SHA256 /s My /sha1 $cert[0].Thumbprint $signed | Out-Null
if($LASTEXITCODE -ne 0){throw 'Sign failed'}
$b=[IO.File]::ReadAllBytes($signed);$pe=[BitConverter]::ToInt32($b,60);$off=[BitConverter]::ToUInt32($b,$pe+24+112+32);$len=[BitConverter]::ToUInt32($b,$off)
if([BitConverter]::ToUInt16($b,$pe+4) -ne 0xaa64){throw 'Driver architecture'}
Add-Type -AssemblyName System.Security
$p=New-Object byte[] ($len-8);[Array]::Copy($b,$off+8,$p,0,$p.Length)
$cms=New-Object System.Security.Cryptography.Pkcs.SignedCms;$cms.Decode($p);$cms.CheckSignature($true)
if($cms.SignerInfos[0].Certificate.Thumbprint -ne $cert[0].Thumbprint){throw 'Signature identity'}
[pscustomobject]@{signed=$signed;sha256=(Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$b.Length;cms_verified=$true;unsigned_sha256=(Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
'''
(w/'private/Finish-G101-Build.ps1').write_text(ps)
print('source/object/tool inputs verified; signing script prepared')
