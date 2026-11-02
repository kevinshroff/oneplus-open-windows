"""Generate data-only identities for the native metadata diagnostic."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--records',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(exist_ok=False)
w=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
cb=lambda b:'{'+','.join('0x%02x'%v for v in b)+'}'
rows=[];text=['/* Generated identities only; no proprietary instructions. */',
 'typedef struct { UINT32 ImageBytes,TextRva,TextBytes,ProtocolCount; UINT32 ProtocolRva[2]; UINT32 RelocCount; CONST UINT32 *Reloc; UINT8 TextHash[32]; } G128_IMAGE;',
 'typedef struct { CONST CHAR16 *Name; UINTN Bytes; UINT8 Hash[32],ConfigHash[32]; } G128_METADATA;']
for n,path,expected,protos in [
 ('Pil',w.parent/'charging-G107/private/installed-loaders/PILDxe.efi','75dd928e1333044a9c7de275753e61b3c44ad5efb3051c62c3a12aa08f559716',[0x16188]),
 ('Scm',w.parent/'charging-G127/private/ScmDxe-G80.efi','847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab',[0xe0e8,0xe140])]:
 raw=path.read_bytes();assert sha(raw)==expected;pe=pefile.PE(data=raw);assert pe.OPTIONAL_HEADER.ImageBase==0
 sections=[s for s in pe.sections if s.Characteristics&0x20000000];assert len(sections)==1;s=sections[0]
 fixes=[e.rva-s.VirtualAddress for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type and s.VirtualAddress<=e.rva<s.VirtualAddress+s.Misc_VirtualSize]
 assert all(e.type==10 for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type and s.VirtualAddress<=e.rva<s.VirtualAddress+s.Misc_VirtualSize)
 image=pe.get_memory_mapped_image();h=bytes.fromhex(sha(image[s.VirtualAddress:s.VirtualAddress+s.Misc_VirtualSize]))
 text+=['STATIC CONST UINT32 m%sReloc[] = {%s};'%(n,','.join(hex(v)for v in fixes)),
 'STATIC CONST G128_IMAGE m%sImage = {%s,%s,%s,%s,{%s},%s,m%sReloc,%s};'%(n,pe.OPTIONAL_HEADER.SizeOfImage,hex(s.VirtualAddress),s.Misc_VirtualSize,len(protos),','.join(hex(v)for v in protos),len(fixes),n,cb(h))]
 (a.output/(n+'-mapped.bin')).write_bytes(image)
 allfix=[e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type]
 assert all(e.type==10 for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type)
 (a.output/(n+'-all-relocs.bin')).write_bytes(struct.pack('<'+'I'*len(allfix),*allfix))
 rows.append({'name':n,'PE_sha256':sha(raw),'image_bytes':pe.OPTIONAL_HEADER.SizeOfImage,'text_RVA':s.VirtualAddress,'text_bytes':s.Misc_VirtualSize,'text_sha256':h.hex(),'DIR64_offsets_within_text':fixes,'protocol_RVAs':protos})
files=[]
for name,file in [('FULL_ADSP_DTB','adsp_dtb.mdt'),('FULL_ADSP','adsp.mdt')]:
 data=(w.parent/'charging-G118/private/firmware-input/firmware/image'/file).read_bytes();cfg=(a.records/(name+'-config.bin')).read_bytes();assert len(cfg)==568
 files.append({'name':name,'file':file,'bytes':len(data),'sha256':sha(data),'config_sha256':sha(cfg)})
text.append('STATIC CONST G128_METADATA mMetadata[] = {')
for f in files:text.append(' {L"%s",%s,%s,%s},'%(f['name'],f['bytes'],cb(bytes.fromhex(f['sha256'])),cb(bytes.fromhex(f['config_sha256']))))
text.append('};')
manifest=(w.parent/'charging-G118/private/firmware-input/capture.json').read_bytes();text.append('STATIC CONST UINT8 mInputDigest[32] = '+cb(bytes.fromhex(sha(manifest)))+';')
(a.output/'OpenPilMetadataBindings.h').write_text('\n'.join(text)+'\n')
(a.output/'identities.json').write_text(json.dumps({'images':rows,'metadata':files,'input_manifest_sha256':sha(manifest),'native_operations':0},indent=2)+'\n');print(json.dumps({'images':len(rows),'metadata':len(files),'input_digest':sha(manifest)}))
