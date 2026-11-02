"""Preserve qualified VM source/build, then select read-only G18 marker firmware."""
from pathlib import Path
import hashlib,json,shlex,subprocess,tarfile,time
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta')
W=R/'work/maintenance-G18/firmware-trial';P=W/'private'
G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
sha=lambda b:hashlib.sha256(b).hexdigest()
def guest(code):return subprocess.check_output(['colima','ssh','--','python3','-'],input=code.encode())
assert not (W/'source-change-receipt.json').exists()
code=f'''
from pathlib import Path
import hashlib,json,os
r=Path({G!r});w=Path({str(R/'work/boot-G16')!r})
h=json.loads((w/'build-apply/source-hashes.json').read_text())
pcd='Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc'
h[pcd]=hashlib.sha256((w/'PcdsFixedAtBuild-undo.dsc.inc').read_bytes()).hexdigest()
for n,x in h.items():assert hashlib.sha256((r/n).read_bytes()).hexdigest()==x,n
v=r.parent/'G17-r2-audit-native.wim';m=Path({str(R/'work/control-G17/private/G17-r2-audit.wim')!r})
assert v.is_file() and m.is_file() and v.stat().st_size==m.stat().st_size==644359620
sh=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=sh(v);assert sh(m)==a
if not v.is_symlink():
 saved=v.with_name(v.name+'.verified-duplicate')
 assert not saved.exists();v.rename(saved)
 try:
  v.symlink_to(m);assert sh(v)==a
 except BaseException:
  v.unlink(missing_ok=True);saved.rename(v);raise
 saved.unlink()
print(json.dumps({{'qualified_source_files':h,'deduplicated_wim_sha256':a,'free_bytes':__import__('shutil').disk_usage('/').free}}))
'''
pre=json.loads(guest(code));(W/'source-hashes-before.json').write_text(json.dumps(pre,indent=2)+'\n')
print('Qualified sources match; verified duplicate WIM replaced with shared preserved file. Free bytes',pre['free_bytes'],flush=True)
archive=P/'pretrial-build.tar.gz';assert not archive.exists()
with archive.open('xb') as f:
 subprocess.run(['colima','ssh','--','tar','-czf','-','-C',G,'Build/KailuaPkg'],stdout=f,check=True)
with tarfile.open(archive,'r:gz') as t:
 names=t.getnames();assert 'Build/KailuaPkg/oneplus-open.img' in names
 old=t.extractfile('Build/KailuaPkg/oneplus-open.img').read()
 baseline=(R/'work/boot-G16/build-undo/boot_a.img').read_bytes();assert old==baseline
print('Previous build archive verified',archive.stat().st_size,flush=True)
code=f'''
from pathlib import Path
import hashlib,json
r=Path({G!r});w=Path({str(W)!r});p=w/'private'
h=json.loads((w/'source-hashes-before.json').read_text())['qualified_source_files']
for n,x in h.items():assert hashlib.sha256((r/n).read_bytes()).hexdigest()==x,n
changes=[('Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc','gAndromedaPkgTokenSpaceGuid.PcdOpenBringupMode|11','gAndromedaPkgTokenSpaceGuid.PcdOpenBringupMode|9'),('Platforms/AndromedaPkg/Library/DeviceBootManagerLib/OpenGptSnapshot.c','"GPTG15  "','"GPTG18T1"')]
receipt={{}}
for i,(n,a,b) in enumerate(changes):
 f=r/n;before=f.read_bytes();s=before.decode();assert s.count(a)==1
 after=s.replace(a,b).encode();save=p/('before-'+str(i)+'-'+f.name);assert not save.exists();save.write_bytes(before)
 f.write_bytes(after);assert f.read_bytes()==after
 receipt[n]={{'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),'replacement':[a,b],'preserved_before':save.name}}
(w/'source-change-receipt.json').write_text(json.dumps(receipt,indent=2)+'\\n')
print(json.dumps(receipt))
'''
print(guest(code).decode())
(W/'prepare-receipt.json').write_text(json.dumps({'source_guard_files':len(pre['qualified_source_files']),'previous_build_archive_bytes':archive.stat().st_size,'previous_build_archive_sha256':sha(archive.read_bytes()),'previous_build_image_sha256':sha(old),'deduplicated_wim_sha256':pre['deduplicated_wim_sha256'],'mode':9,'acpi_marker':'GPTG18T1','gpt_migration_called_in_mode9':False},indent=2)+'\n')
