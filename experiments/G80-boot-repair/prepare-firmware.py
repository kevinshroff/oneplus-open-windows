from pathlib import Path
import json,hashlib,subprocess,io,tarfile
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=R/'work/boot-repair-G80';G=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms');D=G/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
files=['OpenBootRepairRecovery.c','OpenPinnedBlockIo.h','OpenPinnedBlockIo.c','OpenSha256.h','OpenG80GptTypeMigration.h','OpenG80GptTypeMigration.c','OpenG80GoldenData.h','OpenPinnedPlanIdentity.h']
code='''from pathlib import Path
import hashlib,json,tarfile
R=Path(%r);W=R/'work/boot-repair-G80';G=Path(%r);D=G/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=json.loads((R/'work/recovery-G79/private/firmware-build-usb2-ro/source-hashes.json').read_text())
for n,h in base.items():assert sha(G/n)==h,n
save=W/'private/firmware-baseline';save.mkdir(exist_ok=True)
with tarfile.open(save/'sources.tar.gz','w:gz') as t:
 for n in base:t.add(G/n,arcname=n)
(save/'source-hashes.json').write_text(json.dumps(base,indent=2))
paths=%r;changes={}
for n in paths:
 p=D/n;assert not p.exists();p.write_bytes((W/'scripts'/n).read_bytes());changes[str(p.relative_to(G))]={'new':sha(p)}
p=D/'G80-pinned-plan.bin';assert not p.exists();p.write_bytes((W/'private/G80-pinned-plan.bin').read_bytes());changes[str(p.relative_to(G))]={'new':sha(p)}
p=D/'DeviceBootManagerLib.inf';old=p.read_text();assert old.count('  OpenReadOnlyRecovery.c\\n')==1
s=old.replace('  OpenReadOnlyRecovery.c\\n','  OpenReadOnlyRecovery.c\\n  OpenBootRepairRecovery.c\\n  OpenPinnedBlockIo.c\\n  OpenG80GptTypeMigration.c\\n');p.write_text(s);changes[str(p.relative_to(G))]={'old':base[str(p.relative_to(G))],'new':sha(p)}
p=D/'OpenBringupDiagnostics.c';old=p.read_text();a='    if (FixedPcdGet32 (PcdOpenBringupMode) == 12) {';assert old.count(a)==1
s=old.replace(a,'    if (FixedPcdGet32 (PcdOpenBringupMode) == 13 || FixedPcdGet32 (PcdOpenBringupMode) == 14) {\\n      if (!ContinueWindows) { DEBUG ((DEBUG_ERROR, "G80 USB prerequisites refused\\\\n")); CpuDeadLoop (); }\\n      OpenRunBootRepairUsb ();\\n      return;\\n    }\\n'+a)
s=s.replace('VOID OpenRunReadOnlyUsbRecovery (VOID);','VOID OpenRunBootRepairUsb (VOID);\\nVOID OpenRunReadOnlyUsbRecovery (VOID);');p.write_text(s);changes[str(p.relative_to(G))]={'old':base[str(p.relative_to(G))],'new':sha(p)}
p=G/'Platforms/KailuaPkg/Kailua.fdf';old=p.read_text();(save/'Kailua.fdf').write_text(old)
a='[FV.FvMain]';assert old.count(a)==1
# Append the immutable hash map to the compressed FV, without changing the4MiB FD.
s=old.replace('  # Secure Boot Key Enroll','  FILE FREEFORM = 2e037fd2-644f-4b03-b77a-bfb9330d70d8 {\\n    SECTION RAW = Platforms/AndromedaPkg/Library/DeviceBootManagerLib/G80-pinned-plan.bin\\n  }\\n\\n  # Secure Boot Key Enroll',1);assert s!=old;p.write_text(s);changes[str(p.relative_to(G))]={'old':hashlib.sha256(old.encode()).hexdigest(),'new':sha(p)}
p=G/'Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc';old=p.read_text();assert old.count('PcdOpenBringupMode|12')==1;p.write_text(old.replace('PcdOpenBringupMode|12','PcdOpenBringupMode|13'));changes[str(p.relative_to(G))]={'old':base[str(p.relative_to(G))],'new':sha(p)}
(W/'captures/firmware-source-changes.json').write_text(json.dumps(changes,indent=2));print('G80 source and immutable raw plan staged; FD/RAM/vendor binaries unchanged')
'''%(str(R),str(G),files)
r=subprocess.run(['colima','ssh','--','python3','-'],input=code.encode(),stdout=subprocess.PIPE,stderr=subprocess.STDOUT);print(r.stdout.decode());r.check_returncode()
