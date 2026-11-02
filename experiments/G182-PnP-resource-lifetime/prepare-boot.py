"""Seal the audited firmware and next-boot controls before retiring the current owner."""
from pathlib import Path
import json,hashlib,zipfile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
a=json.loads((p/'image-audit.json').read_text());assert a['passed']and not a['unexpected']
files={'boot-G182-resources.img':p/'boot-G182-resources.img','G182-status.exe':p/'G182-status.exe','G155-read-DSP.exe':w.parent/'charging-G155/private/G155-read-DSP.exe','G154-install-arm64.exe':w.parent/'charging-G155/private/release/G154-install-arm64.exe'}
for n in ['OpenG182.sys','OpenG182.inf','OpenG182.cat','G182-public.cer']:files[n]=p/n
for n in ['Refresh-Debugger-G182.ps1','G182-Restore-EEM.ps1']:files[n]=w/n
assert sha(files['G154-install-arm64.exe'])=='d6fb3079f3b02aef839724ec783be623af9b8c7c4ca9f8e174e599f2c631d5c7'
assert sha(files['G155-read-DSP.exe'])=='c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa'
# Existing fresh-identity fastboot guards, one-shot debugger, and one boot command.
s=(w.parent/'charging-G181/Boot-Existing-Image-G181.ps1').read_text();cut=s.index('$tasks=')
s='''param([switch]$VerifyOnly)
$ErrorActionPreference='Stop'
$root=Join-Path $env:USERPROFILE 'Downloads\\Open-G17\\payloads'
$release=Get-Content -LiteralPath (Join-Path $root 'G182-release.json') -Raw|ConvertFrom-Json
if($release.campaign -ne 'G182' -or $release.action -ne 'temporary_boot' -or $release.image_sha256 -ne '__IMAGE__'){throw 'Release identity'}
foreach($f in $release.files){
 if($f.name -notmatch '^[a-zA-Z0-9_.-]+$' -or $f.name -in @('.','..')){throw 'Unsafe release filename'}
 $p=Join-Path $root $f.name
 if((Get-Item -LiteralPath $p).Length -ne $f.bytes -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $f.sha256){throw ('Release file identity: '+$f.name)}
}
$fb=Join-Path $env:USERPROFILE 'Downloads\\platform-tools\\fastboot.exe'
if((Get-FileHash -LiteralPath $fb -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86'){throw 'Fastboot identity'}
if($VerifyOnly){@{phase='G182_release_verified';files=$release.files.Count;phone_commands=0}|ConvertTo-Json -Compress;exit 0}
'''.replace('__IMAGE__',a['image_sha256'])+s[cut:]
s=s.replace("Join-Path $root ('runs\\'", "Join-Path $root ('G182-runs\\'").replace('boot-G155-main-auth.img','boot-G182-resources.img').replace('Refresh-Debugger-G181.ps1','Refresh-Debugger-G182.ps1').replace('G181_fresh_debug_listener','G182_fresh_debug_listener')
(w/'Boot-G182.ps1').write_text(s);files['Boot-G182.ps1']=w/'Boot-G182.ps1'
m={'campaign':'G182','action':'temporary_boot','image_sha256':a['image_sha256'],'scope':'Supplementary ACPI resources and resource-only PnP driver. No sensor,GLINK or battery ownership qualification.','partition_flashes':0,'same_boot_PAS_retries':0,'files':[{'name':n,'sha256':sha(f),'bytes':f.stat().st_size}for n,f in files.items()]}
(p/'G182-release.json').write_text(json.dumps(m,indent=2)+'\n');files['G182-release.json']=p/'G182-release.json'
(p/'release-source-files.json').write_text(json.dumps({n:{'path':str(f),'sha256':sha(f)}for n,f in files.items()},indent=2)+'\n')
with zipfile.ZipFile(p/'G182-release.zip','x',zipfile.ZIP_DEFLATED)as z:
 for n,f in files.items():z.write(f,n)
print({'files':len(files),'image_sha256':a['image_sha256'],'phone_operations':0})
