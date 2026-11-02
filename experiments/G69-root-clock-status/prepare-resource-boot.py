"""Offline-only one-time BCD edit, whole-store/file audit and exact undo plan."""
from pathlib import Path
import base64,hashlib,json,re,shutil,subprocess
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private';R=Relay('resource-boot-preparation.json');s=R.s
fresh=json.loads((W/'fresh-FAT.json').read_text())
assert fresh['phase']=='fresh_complete_FAT_reconstructed_from_actual_small_reads_and_verified_whole_hash'
before=Path(fresh['file']);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(before)==fresh['sha256']
bcd=P/'G69-bcd-before.bcd'
if not bcd.exists():subprocess.run(['colima','ssh','--','mcopy','-i',str(before),'::/EFI/Microsoft/Boot/BCD',str(bcd)],check=True)
loader='{98a7ea09-cd06-11f1-9482-c0a810591275}'
script=P/'G69-prepare-offline-bcd.ps1'
source=r'''$ErrorActionPreference='Stop'
$Root=$PSScriptRoot
$Source=Join-Path $Root 'G69-bcd-before.bcd'
$Before=Join-Path $Root 'G69-bcd-before-export.bcd'
$After=Join-Path $Root 'G69-bcd-after.bcd'
$Inspect=Join-Path $Root 'G69-bcd-inspect.bcd'
if((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLower() -ne 'BEFOREHASH'){throw 'Offline source mismatch'}
foreach($Name in @('G69-bcd-before-export.bcd','G69-bcd-after.bcd','G69-bcd-before.reg','G69-bcd-after.reg','G69-loader-private.txt','G69-bcd-inspect.bcd')){
 if(Test-Path -LiteralPath (Join-Path $Root $Name)){throw 'Preserve existing offline outputs'}
}
Copy-Item -LiteralPath $Source -Destination $Before
Copy-Item -LiteralPath $Source -Destination $After
Copy-Item -LiteralPath $Source -Destination $Inspect
$Enum=@(& bcdedit.exe /store $Inspect /enum 'LOADER' /v)
if($LASTEXITCODE -ne 0){throw 'Existing loader not found'}
$Text=$Enum -join "`r`n"
if($Text -notmatch [regex]::Escape('LOADER') -or $Text -notmatch [regex]::Escape('\OpenG18\G20-acpi-canary.wim')){throw 'Existing loader identity/path differs'}
if($Text -notmatch 'winpe\s+Yes'){throw 'Existing loader is not WinPE'}
$Text|Set-Content -LiteralPath (Join-Path $Root 'G69-loader-private.txt') -Encoding Unicode
& bcdedit.exe /store $After /bootsequence 'LOADER' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Offline bootsequence edit failed'}
foreach($Item in @(@{Tag='G69_BCD_BEFORE';File=$Before;Out='G69-bcd-before.reg'},@{Tag='G69_BCD_AFTER';File=$After;Out='G69-bcd-after.reg'})){
 $Hive='HKLM\'+$Item.Tag
 $Key='Registry::HKEY_LOCAL_MACHINE\'+$Item.Tag
 if(Test-Path -LiteralPath $Key){throw 'Temporary offline hive already loaded'}
 & reg.exe load $Hive $Item.File | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Offline hive load failed'}
 try{
  $Desc=$Key+'\Description'
  $Seen=(Get-ItemProperty -LiteralPath $Desc).KeyName
  if($Item.Tag -eq 'G69_BCD_BEFORE'){
   if($Seen -notmatch '^BCD[0-9A-Fa-f]{8}$'){throw 'Unexpected original store metadata'}
   $OriginalKeyName=$Seen
  }else{
   if($Seen -notmatch '^BCD[0-9A-Fa-f]{8}$'){throw 'Unexpected candidate metadata'}
   if(-not $OriginalKeyName){throw 'Original metadata not recorded'}
   if($Seen -ne $OriginalKeyName){Set-ItemProperty -LiteralPath $Desc -Name KeyName -Value $OriginalKeyName}
  }
  & reg.exe export $Hive (Join-Path $Root $Item.Out) | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Offline hive export failed'}
 }finally{
  & reg.exe unload $Hive | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Offline hive unload failed'}
 }
}
Write-Output 'Existing RAM loader verified; offline one-time sequence prepared; temporary hives unloaded.'
'''.replace('BEFOREHASH',sha(bcd)).replace('LOADER',loader)
if script.exists():assert script.read_text()==source
else:
 with script.open('x')as f:f.write(source)
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
for p in [bcd,script]:
 h=sha(p);assert op('stage-'+p.name,'put',file=p,path=p.name)['sha256']==h
host='C:\\Users\\PUBLIC_USER\\Downloads\\Open-G17\\payloads\\'
op('single-offline-edit','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',host+script.name])
for name in ['G69-bcd-before.reg','G69-bcd-after.reg','G69-bcd-after.bcd','G69-loader-private.txt']:
 op('get-'+name,'get',path=host+name,save=P/name)
def parse(path,tag):
 text=re.sub(r'\\\r?\n\s*','',path.read_text(encoding='utf-16'));result={};key=None;prefix='HKEY_LOCAL_MACHINE\\'+tag
 for line in text.splitlines():
  line=line.strip()
  if not line or line=='Windows Registry Editor Version 5.00':continue
  if line.startswith('[')and line.endswith(']'):
   full=line[1:-1];assert full==prefix or full.startswith(prefix+'\\')
   key=full[len(prefix):].lstrip('\\').lower();assert key not in result;result[key]={};continue
  assert key is not None and'='in line
  name,value=line.split('=',1);name=name.lower();assert name not in result[key]
  if value.startswith(('hex:','hex(')):value=re.sub(r'\s+','',value).lower()
  result[key][name]=value
 return result
a=parse(P/'G69-bcd-before.reg','G69_BCD_BEFORE');b=parse(P/'G69-bcd-after.reg','G69_BCD_AFTER')
seq=r'objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\elements\24000002'
assert seq not in a,'Understand an existing sequence before replacing it'
assert b.keys()-a.keys()=={seq}and not a.keys()-b.keys()and all(a[k]==b[k]for k in a)
assert b[seq].keys()=={'"element"'};value=b[seq]['"element"'];assert value.startswith('hex(7):')
assert bytes.fromhex(value.split(':',1)[1].replace(',','')).decode('utf-16le')==loader+'\0\0'
after=P/'userdata-G69-onetime.img'
if not after.exists():
 shutil.copyfile(before,after)
 subprocess.run(['colima','ssh','--','mcopy','-o','-i',str(after),str(P/'G69-bcd-after.bcd'),'::/EFI/Microsoft/Boot/BCD'],check=True)
file_code='''from pathlib import Path
import hashlib,json,subprocess,tempfile,sys
r={}
with tempfile.TemporaryDirectory()as tmp:
 for i,n in enumerate(subprocess.check_output(['mdir','-a','-/','-b','-i',sys.argv[1],'::/'],text=True).splitlines()):
  if n.endswith('/'):continue
  assert n.startswith('::/');p=Path(tmp)/str(i)
  subprocess.run(['mcopy','-i',sys.argv[1],n,str(p)],check=True,stdout=subprocess.DEVNULL)
  r[n[3:]]=hashlib.sha256(p.read_bytes()).hexdigest()
print(json.dumps(r))
'''
def files(image):return json.loads(subprocess.check_output(['colima','ssh','--','python3','-c',file_code,str(image)]))
old_files,new_files=files(before),files(after)
assert old_files.keys()==new_files.keys()and len(old_files)==76
assert[k for k in old_files if old_files[k]!=new_files[k]]==['EFI/Microsoft/Boot/BCD']
x,y=before.read_bytes(),after.read_bytes();assert len(x)==len(y)==268435456 and x[:512]==y[:512]
reserved=int.from_bytes(y[14:16],'little')*int.from_bytes(y[11:13],'little')
fat_bytes=int.from_bytes(y[36:40],'little')*int.from_bytes(y[11:13],'little')
assert y[16]==2 and y[reserved:reserved+fat_bytes]==y[reserved+fat_bytes:reserved+2*fat_bytes]
fsck=subprocess.run(['colima','ssh','--','fsck.fat','-n',str(after)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(P/'resource-FAT-fsck.log').write_bytes(fsck.stdout);assert fsck.returncode==0
changes=[{'offset':o,'before':base64.b64encode(x[o:o+4096]).decode(),'after':base64.b64encode(y[o:o+4096]).decode()}for o in range(0,len(x),4096)if x[o:o+4096]!=y[o:o+4096]]
assert 0<len(changes)<=1024
plan={'version':1,'target':'userdata','prefix_bytes':len(x),'before_sha256':hashlib.sha256(x).hexdigest(),'after_sha256':hashlib.sha256(y).hexdigest(),'changes':changes}
undo=dict(plan,before_sha256=plan['after_sha256'],after_sha256=plan['before_sha256'],changes=[dict(c,before=c['after'],after=c['before'])for c in changes])
restored=bytearray(y)
for c in undo['changes']:restored[c['offset']:c['offset']+4096]=base64.b64decode(c['after'])
assert bytes(restored)==x
for name,data in [('G69-FAT-onetime.json',plan),('G69-FAT-onetime-inverse.json',undo)]:
 path=P/name;encoded=json.dumps(data,indent=2)+'\n'
 if path.exists():assert path.read_text()==encoded
 else:
  with path.open('x')as f:f.write(encoded)
s.update(phase='offline_one_time_BCD_and_FAT_plan_audited_not_activated',source_FAT_sha256=fresh['sha256'],loader=loader,
 G17_default_and_all_original_BCD_keys_values_unchanged=True,sole_added_BCD_key=seq,before_BCD_keys=len(a),after_BCD_keys=len(b),
 only_changed_file='EFI/Microsoft/Boot/BCD',files_compared=76,FAT_copies_identical=True,VBR_512_bytes_unchanged=True,fsck_exit=0,
 inverse_exactly_restores_fresh_FAT=True,before_sha256=plan['before_sha256'],after_sha256=plan['after_sha256'],changed_sectors=len(changes),
 plan_sha256=sha(P/'G69-FAT-onetime.json'),inverse_sha256=sha(P/'G69-FAT-onetime-inverse.json'),raw_writes=0)
R.persist();print(json.dumps({k:s[k]for k in ['phase','changed_sectors','before_BCD_keys','after_BCD_keys','raw_writes']}),flush=True)
