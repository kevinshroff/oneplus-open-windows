from pathlib import Path
import hashlib,json,subprocess,shlex,tarfile,io
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=R/'work/recovery-G79';G=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
def vm(code): return subprocess.check_output(['colima','ssh','--','python3','-'],input=code.encode())
code=r'''from pathlib import Path
import hashlib,json,tarfile
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=R/'work/recovery-G79';G=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=json.loads((R/'work/boot-G16/build-undo/source-hashes.json').read_text())
for n,x in h.items(): assert sha(G/n)==x,n
B=G/'Build/KailuaPkg';F=B/'DEBUG_CLANGPDB/FV/Ffs'
catalog={str(p.relative_to(F)):sha(p) for p in F.rglob('*.ffs')}
assert len(catalog)>200
out=W/'private/firmware-before';out.mkdir()
(out/'source-hashes.json').write_text(json.dumps(h,indent=2))
(out/'ffs-hashes.json').write_text(json.dumps(catalog,indent=2))
with tarfile.open(out/'sources.tar.gz','w:gz') as t:
 for n in h:t.add(G/n,arcname=n)
with tarfile.open(out/'firmware.tar.gz','w:gz') as t:
 for p in F.rglob('*.ffs'):t.add(p,arcname='Ffs/'+str(p.relative_to(F)))
 for n in ['BdsDxe','RamPartitionDxe','SettingsManagerDxe','IdentityAndAuthManagerDxe','MuCryptoDxe']:
  t.add(B/('DEBUG_CLANGPDB/AARCH64/'+n+'.efi'),arcname=n+'.efi')
 for n in ['oneplus-open.img','DEBUG_CLANGPDB/FV/SM8550_EFI.fd']:
  t.add(B/n,arcname=n)
D=G/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
changes={}
for n in ['ReadOnlyBlockIo.h','ReadOnlyBlockIo.c','OpenScsiWriteProtect.h','OpenReadOnlyRecovery.c']:
 p=D/n;assert not p.exists();b=(W/'scripts'/n).read_bytes();p.write_bytes(b);changes[str(p.relative_to(G))]={'new':sha(p)}
p=D/'DeviceBootManagerLib.inf';b=p.read_text();assert b.count('  OpenBringupDiagnostics.c\n')==1
p.write_text(b.replace('  OpenBringupDiagnostics.c\n','  OpenBringupDiagnostics.c\n  OpenReadOnlyRecovery.c\n  ReadOnlyBlockIo.c\n'))
changes[str(p.relative_to(G))]={'old':h[str(p.relative_to(G))],'new':sha(p)}
p=D/'OpenBringupDiagnostics.c';b=p.read_text();a='    if (FixedPcdGet32 (PcdOpenBringupMode) >= 7) {';assert b.count(a)==1
b=b.replace(a,'    if (FixedPcdGet32 (PcdOpenBringupMode) == 12) {\n      if (!ContinueWindows) { DEBUG ((DEBUG_ERROR, "G79 USB prerequisites refused\\n")); CpuDeadLoop (); }\n      OpenRunReadOnlyUsbRecovery ();\n      CpuDeadLoop ();\n    }\n'+a)
b=b.replace('VOID OpenCollectBootStorageEvidence','VOID OpenRunReadOnlyUsbRecovery (VOID);\nVOID OpenCollectBootStorageEvidence',1)
p.write_text(b);changes[str(p.relative_to(G))]={'old':h[str(p.relative_to(G))],'new':sha(p)}
p=G/'Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc';b=p.read_text();a='PcdOpenBringupMode|11';assert b.count(a)==1;p.write_text(b.replace(a,'PcdOpenBringupMode|12'));changes[str(p.relative_to(G))]={'old':h[str(p.relative_to(G))],'new':sha(p)}
(W/'captures/firmware-source-changes.json').write_text(json.dumps(changes,indent=2))
print(json.dumps({'qualified_baseline_sources':len(h),'baseline_ffs':len(catalog),'changes':changes}))
'''
print(vm(code).decode())
