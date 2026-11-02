"""Audit marker firmware against preserved complete prior build and G16 sources."""
from pathlib import Path
import gzip,hashlib,io,json,shlex,struct,subprocess,tarfile
import pefile
W=Path(__file__).resolve().parent;R=W.parents[2];P=W/'private';G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms';B=G+'/Build/KailuaPkg'
sha=lambda b:hashlib.sha256(b).hexdigest()
def guest(cmd):return subprocess.check_output(['colima','ssh','--','bash','-lc',cmd])
def read(p):return guest('cat '+shlex.quote(p))
out=W/'build';assert not out.exists();out.mkdir()
log=read('/tmp/open-G18-marker-build.log');assert b'0121 Images Verified' in log and b'PROGRESS - Success' in log and b'error:' not in log.lower()
(out/'build.log').write_bytes(log)
h=json.loads((W/'source-hashes-before.json').read_text())['qualified_source_files']
changes=json.loads((W/'source-change-receipt.json').read_text());assert len(changes)==2
h.update({n:x['after_sha256'] for n,x in changes.items()})
for n,x in h.items():assert sha(read(G+'/'+n))==x,n
(out/'source-hashes.json').write_text(json.dumps(h,indent=2)+'\n')
archive=guest('cd '+shlex.quote(G)+' && tar -czf - '+' '.join(map(shlex.quote,h)))
with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as t:
 for m in t.getmembers():assert sha(t.extractfile(m).read())==h[m.name]
(out/'source-state.tar.gz').write_bytes(archive)
image=read(B+'/oneplus-open.img');assert image[:8]==b'ANDROID!' and struct.unpack_from('<I',image,40)[0]==3
assert struct.unpack_from('<I',image,12)[0]==0 and struct.unpack_from('<I',image,20)[0]==1580 and 1_000_000<len(image)<16_000_000
(out/'boot_a.img').write_bytes(image)
shim=read(G+'/BootShim/BootShim.bin');assert len(shim)==112
old_apply=(R/'work/boot-G16/build-apply/boot_a.img').read_bytes()
new_kernel=gzip.decompress(image[4096:4096+struct.unpack_from('<I',image,8)[0]])
old_kernel=gzip.decompress(old_apply[4096:4096+struct.unpack_from('<I',old_apply,8)[0]])
assert len(new_kernel)==len(old_kernel)==112+4194304 and new_kernel[:112]==old_kernel[:112]==shim
assert new_kernel[112:]==read(B+'/DEBUG_CLANGPDB/FV/SM8550_EFI.fd')
assert image[:8]+bytes(4)+image[12:4096]==old_apply[:8]+bytes(4)+old_apply[12:4096]
(out/'BootShim.bin').write_bytes(shim)

with tarfile.open(P/'pretrial-build.tar.gz','r:gz') as old:
 prefix='Build/KailuaPkg/DEBUG_CLANGPDB/'
 catalog_before={m.name[len(prefix+'FV/Ffs/'):]:sha(old.extractfile(m).read()) for m in old.getmembers() if m.name.startswith(prefix+'FV/Ffs/') and m.name.endswith('.ffs')}
 code='from pathlib import Path;import hashlib,json;r=Path('+repr(B+'/DEBUG_CLANGPDB/FV/Ffs')+');print(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.rglob("*.ffs")},sort_keys=True))'
 catalog=json.loads(guest('python3 -c '+shlex.quote(code)));assert catalog.keys()==catalog_before.keys()
 changed=[n for n in catalog if catalog[n]!=catalog_before[n]]
 bds='6D33944A-EC75-4855-A54D-809C75241F6CBdsDxe/6D33944A-EC75-4855-A54D-809C75241F6C.ffs'
 compact='9E21FD93-9C72-4c15-8C4B-E77F1DB2D792FVMAIN_COMPACT/9E21FD93-9C72-4c15-8C4B-E77F1DB2D792.ffs'
 extras={'0CCF27CF-E68D-4279-96B0-8A4E1CDFF10CSettingsManagerDxe/0CCF27CF-E68D-4279-96B0-8A4E1CDFF10C.ffs':'SettingsManagerDxe.efi','F8126429-7B88-4AD2-98C4-402CBE26F9A8IdentityAndAuthManagerDxe/F8126429-7B88-4AD2-98C4-402CBE26F9A8.ffs':'IdentityAndAuthManagerDxe.efi','C9B8B0B7-9C85-46E8-B343-362FBD26E8F3MuCryptoDxe/C9B8B0B7-9C85-46E8-B343-362FBD26E8F3.ffs':'MuCryptoDxe.efi'}
 assert {bds,compact}.issubset(changed) and set(changed).issubset({bds,compact}|set(extras)),changed
 proof={'Android_header_only_kernel_size_differs':True,'decompressed_kernel_bytes':len(new_kernel),'decompressed_FD_exact_build_FD':True,'BootShim_byte_identical_to_G16_apply':True,'BootShim_bytes':len(shim),'BootShim_sha256':sha(shim),'baseline':'complete preserved G16 undo build','changed':changed,'total_ffs':len(catalog),'unchanged_ffs':len(catalog)-len(changed)}
 for n in changed:
  if n not in extras:continue
  name=extras[n];a=old.extractfile(prefix+'AARCH64/'+name).read();b=read(B+'/DEBUG_CLANGPDB/AARCH64/'+name)
  pe=pefile.PE(data=a);ds=[x for x in pe.DIRECTORY_ENTRY_DEBUG if x.struct.Type==2];assert len(ds)==1
  off=ds[0].struct.PointerToRawData;assert a[off:off+4]==b[off:off+4]==b'RSDS' and len(a)==len(b)
  assert a[:off+4]+bytes(16)+a[off+20:]==b[:off+4]+bytes(16)+b[off+20:]
  proof[name]={'only_CodeView_GUID_changed':True,'before_sha256':sha(a),'after_sha256':sha(b)}
 for name in ['BdsDxe.efi','RamPartitionDxe.efi']:
  a=old.extractfile(prefix+'AARCH64/'+name).read();b=read(B+'/DEBUG_CLANGPDB/AARCH64/'+name)
  if name=='RamPartitionDxe.efi':assert a==b;proof['RAM_driver_byte_identical']=True
  if name=='BdsDxe.efi':assert b'GPTG18T1' in b and b'GPTG18T1' not in a;proof['marker_compiled_in_BdsDxe']=True
  (out/name).write_bytes(b)
(out/'ffs-hashes.json').write_text(json.dumps(catalog,indent=2)+'\n')
(out/'ffs-hashes-before.json').write_text(json.dumps(catalog_before,indent=2)+'\n')
(out/'firmware-content-verification.json').write_text(json.dumps(proof,indent=2)+'\n')
r={'mode':9,'acpi_marker':'GPTG18T1','image_bytes':len(image),'image_sha256':sha(image),'kernel_bytes':struct.unpack_from('<I',image,8)[0],'source_files':len(h),'verified_build_images':121,'firmware_scope':proof,'native_installation':'not yet applied'}
(out/'receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
