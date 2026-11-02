from pathlib import Path
import subprocess,hashlib,json,tarfile,pefile,gzip,struct,shlex,argparse
R=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=R/'work/recovery-G79';G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms';B=G+'/Build/KailuaPkg'
def vm(cmd):return subprocess.check_output(['colima','ssh','--','bash','-lc',cmd])
def read(p):return vm('cat '+shlex.quote(p))
sha=lambda b:hashlib.sha256(b).hexdigest()
a=argparse.ArgumentParser();a.add_argument('--variant',default='r2',choices=['r2','usb2','usb2-ro']);args=a.parse_args()
out=W/('private/firmware-build' if args.variant=='r2' else 'private/firmware-build-'+args.variant);out.mkdir(exist_ok=True)
log=read('/tmp/open-G79-readonly-build-'+args.variant+'.log');assert b'0121 Images Verified' in log and b'PROGRESS - Success' in log and b'error:' not in log.lower();(out/'build.log').write_bytes(log)
changes=json.loads((W/'captures/firmware-source-changes.json').read_text());baseline=json.loads((W/'private/firmware-before/source-hashes.json').read_text())
expected=dict(baseline);expected.update({n:c['new'] for n,c in changes.items()})
for n,h in expected.items():assert sha(read(G+'/'+n))==h,n
(out/'source-hashes.json').write_text(json.dumps(expected,indent=2))
code='from pathlib import Path;import hashlib,json;r=Path('+repr(B+'/DEBUG_CLANGPDB/FV/Ffs')+');print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob("*.ffs")}))'
new=json.loads(vm('python3 -c '+shlex.quote(code)));old=json.loads((W/'private/firmware-before/ffs-hashes.json').read_text());assert new.keys()==old.keys()
changed=[n for n in old if old[n]!=new[n]]
(out/'ffs-hashes.json').write_text(json.dumps(new,indent=2))
img=read(B+'/oneplus-open.img');assert img[:8]==b'ANDROID!' and struct.unpack_from('<I',img,40)[0]==3 and struct.unpack_from('<I',img,12)[0]==0
kernel=gzip.decompress(img[4096:4096+struct.unpack_from('<I',img,8)[0]]);shim=read(G+'/BootShim/BootShim.bin');assert len(shim)==112 and kernel[:112]==shim and kernel[112:]==read(B+'/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')
proof={'variant':args.variant,'sources_verified':len(expected),'firmware_files':len(new),'changed':changed,'bootshim_sha256':sha(shim),'image_sha256':sha(img),'image_bytes':len(img),'mode':12,'source_raw_write_forwarders':0,'physical_usb_test':'pending'}
assert sha(shim)=='1f5950ef61a07aeff91a6435821d54c72942d1d85757a5dfaa50f01513c26115'
assert any('BdsDxe' in n for n in changed) and any('FVMAIN_COMPACT' in n for n in changed)
assert all(any(a in n for a in ['BdsDxe','FVMAIN_COMPACT','SettingsManagerDxe','IdentityAndAuthManagerDxe','MuCryptoDxe']) for n in changed)
with tarfile.open(W/'private/firmware-before/firmware.tar.gz') as t:
 for n in ['SettingsManagerDxe','IdentityAndAuthManagerDxe','MuCryptoDxe','RamPartitionDxe']:
  a=t.extractfile(n+'.efi').read();b=read(B+'/DEBUG_CLANGPDB/AARCH64/'+n+'.efi')
  if a==b:proof[n]='byte_identical';continue
  assert n!='RamPartitionDxe',n
  pe=pefile.PE(data=a);ds=[x for x in pe.DIRECTORY_ENTRY_DEBUG if x.struct.Type==2];assert len(ds)==1
  off=ds[0].struct.PointerToRawData
  assert len(a)==len(b) and a[off:off+4]==b[off:off+4]==b'RSDS'
  assert a[:off+4]+bytes(16)+a[off+20:]==b[:off+4]+bytes(16)+b[off+20:],n
  proof[n]='only_CodeView_GUID_changed'
for n in ['UsbMsdDxe','UsbfnDwc3Dxe','UFSDxe']:
 p='Platforms/KailuaPkg/Device/oneplus-open/Binaries/QcomPkg/Drivers/'+n+'/'+n+'.efi'
 assert read(G+'/'+p)==(R/'work/source-snapshot'/p).read_bytes();proof[n]='source_binary_identical; FFS unchanged'
bds=read(B+'/DEBUG_CLANGPDB/AARCH64/BdsDxe.efi');assert b'G79 read-only USB recovery' in bds.decode('utf-16le',errors='ignore').encode('ascii',errors='ignore') or b'G\x007\x009\x00 \x00r\x00e\x00a\x00d\x00' in bds
(out/'BdsDxe.efi').write_bytes(bds)
(out/'boot-G79-readonly.img').write_bytes(img)
with tarfile.open(out/'source-state.tar.gz','w:gz') as t:
 for n in expected:
  data=read(G+'/'+n);m=tarfile.TarInfo(n);m.size=len(data);import io;t.addfile(m,io.BytesIO(data))
(W/('captures/firmware-verification.json' if args.variant=='r2' else 'captures/firmware-verification-'+args.variant+'.json')).write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
