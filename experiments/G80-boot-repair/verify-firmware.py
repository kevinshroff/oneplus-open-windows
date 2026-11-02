from pathlib import Path
import subprocess,hashlib,json,tarfile,struct,gzip,shlex,argparse,io
import pefile
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=R/'work/boot-repair-G80';G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms';B=G+'/Build/KailuaPkg'
sha=lambda b:hashlib.sha256(b).hexdigest()
def vm(c):return subprocess.check_output(['colima','ssh','--','bash','-lc',c])
def read(p):return vm('cat '+shlex.quote(p))
a=argparse.ArgumentParser();a.add_argument('variant',choices=['apply','undo','normal']);args=a.parse_args();mode={'apply':13,'undo':14,'normal':9}[args.variant]
out=W/('private/firmware-'+args.variant);out.mkdir(exist_ok=True)
log=read('/tmp/open-G80-'+args.variant+'-build.log');assert b'0121 Images Verified' in log and b'PROGRESS - Success' in log and b'error:' not in log.lower();(out/'build.log').write_bytes(log)
changes=json.loads((W/'captures/firmware-source-changes.json').read_text());base=json.loads((W/'private/firmware-baseline/source-hashes.json').read_text());expected=dict(base)
for n,c in changes.items():
 if n.endswith('/PcdsFixedAtBuild.dsc.inc'):continue
 if n.endswith('.c') or n.endswith('.h'):
  p=W/'scripts'/Path(n).name
  if p.exists():c['new']=sha(p.read_bytes())
 expected[n]=c['new']
# The mode is the only per-variant source change.
p='Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc';s=read(G+'/'+p);assert ('PcdOpenBringupMode|'+str(mode)).encode() in s;expected[p]=sha(s)
for n,h in expected.items():assert sha(read(G+'/'+n))==h,n
(out/'source-hashes.json').write_text(json.dumps(expected,indent=2))
changes['Platforms/AndromedaPkg/Library/DeviceBootManagerLib/OpenBootRepairRecovery.c']['new']=expected['Platforms/AndromedaPkg/Library/DeviceBootManagerLib/OpenBootRepairRecovery.c']
(W/'captures/firmware-source-changes.json').write_text(json.dumps(changes,indent=2))
code='from pathlib import Path;import hashlib,json;r=Path('+repr(B+'/DEBUG_CLANGPDB/FV/Ffs')+');print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob("*.ffs")}))'
new=json.loads(vm('python3 -c '+shlex.quote(code)));old=json.loads((R/'work/recovery-G79/private/firmware-build-usb2-ro/ffs-hashes.json').read_text())
added=sorted(set(new)-set(old));removed=sorted(set(old)-set(new));assert len(added)==1 and '2E037FD2-644F-4B03-B77A-BFB9330D70D8' in added[0].upper() and not removed
changed=[n for n in old if old[n]!=new[n]]
assert any('BdsDxe' in n for n in changed) and any('FVMAIN_COMPACT' in n for n in changed)
assert all(any(x in n for x in ['BdsDxe','FVMAIN_COMPACT','SettingsManagerDxe','IdentityAndAuthManagerDxe','MuCryptoDxe','FrontPage']) for n in changed),changed
(out/'ffs-hashes.json').write_text(json.dumps(new,indent=2))
img=read(B+'/oneplus-open.img');assert img[:8]==b'ANDROID!' and struct.unpack_from('<I',img,40)[0]==3 and struct.unpack_from('<I',img,12)[0]==0
kernel=gzip.decompress(img[4096:4096+struct.unpack_from('<I',img,8)[0]]);shim=read(G+'/BootShim/BootShim.bin');fd=read(B+'/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')
assert len(shim)==112 and kernel[:112]==shim and kernel[112:]==fd and len(fd)==4<<20
assert sha(shim)=='1f5950ef61a07aeff91a6435821d54c72942d1d85757a5dfaa50f01513c26115'
proof={'variant':args.variant,'mode':mode,'sources_verified':len(expected),'firmware_files':len(new),'changed':changed,'added':added,'bootshim_sha256':sha(shim),'FD_bytes':len(fd),'image_sha256':sha(img),'image_bytes':len(img),'native_test':'pending; no phone write by build verification'}
with tarfile.open(R/'work/recovery-G79/private/firmware-before/firmware.tar.gz') as t:
 # An incremental relink can regenerate FrontPage's CodeView GUID.
 # Admit it only after the complete FFS matches outside that exact GUID.
 for name in [n for n in changed if 'FrontPage' in n]:
  x=t.extractfile('Ffs/'+name).read();y=read(B+'/DEBUG_CLANGPDB/FV/Ffs/'+name);mz=x.find(b'MZ');assert mz>0
  pe=pefile.PE(data=x[mz:]);ds=[d for d in pe.DIRECTORY_ENTRY_DEBUG if d.struct.Type==2];assert len(ds)==1
  off=mz+ds[0].struct.PointerToRawData;assert len(x)==len(y) and x[off:off+4]==y[off:off+4]==b'RSDS'
  assert x[:off+4]+bytes(16)+x[off+20:]==y[:off+4]+bytes(16)+y[off+20:]
  proof['FrontPage']='complete FFS identical except CodeView GUID'
 for n in ['SettingsManagerDxe','IdentityAndAuthManagerDxe','MuCryptoDxe','RamPartitionDxe']:
  a=t.extractfile(n+'.efi').read();b=read(B+'/DEBUG_CLANGPDB/AARCH64/'+n+'.efi')
  if a==b:proof[n]='byte_identical';continue
  assert n!='RamPartitionDxe'
  pe=pefile.PE(data=a);ds=[x for x in pe.DIRECTORY_ENTRY_DEBUG if x.struct.Type==2];assert len(ds)==1;off=ds[0].struct.PointerToRawData
  assert len(a)==len(b) and a[off:off+4]==b[off:off+4]==b'RSDS'
  assert a[:off+4]+bytes(16)+a[off+20:]==b[:off+4]+bytes(16)+b[off+20:],n
  proof[n]='only_CodeView_GUID_changed'
for n in ['UsbMsdDxe','UsbfnDwc3Dxe','UFSDxe']:
 p='Platforms/KailuaPkg/Device/oneplus-open/Binaries/QcomPkg/Drivers/'+n+'/'+n+'.efi';assert read(G+'/'+p)==(R/'work/source-snapshot'/p).read_bytes();proof[n]='binary and FFS identical to baseline'
# Other platform source hashes include RAM maps, ACPI and Qualcomm loader inputs.
(out/('boot-G80-'+args.variant+'.img')).write_bytes(img);(out/'BdsDxe.efi').write_bytes(read(B+'/DEBUG_CLANGPDB/AARCH64/BdsDxe.efi'))
with tarfile.open(out/'source-state.tar.gz','w:gz') as t:
 for n in expected:
  data=read(G+'/'+n);m=tarfile.TarInfo(n);m.size=len(data);t.addfile(m,io.BytesIO(data))
(W/('captures/firmware-'+args.variant+'.json')).write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2),flush=True)
