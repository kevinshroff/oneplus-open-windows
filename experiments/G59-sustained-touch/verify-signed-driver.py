"""Validate CMS receipt, embedded Authenticode digest and unchanged loadable code.

Certificate-chain production trust is separate and is not claimed here.
"""
from pathlib import Path
import argparse,base64,hashlib,json
import pefile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();W=a.work
s=json.loads((W/'signing.json').read_text())['metadata'];signed=W/'private/G59-signed.sys';unsigned=W/'private/G59-unsigned.sys';data=signed.read_bytes();old=unsigned.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(data)==s['signed_sha256'] and s['cms_signature_verified'] and s['cms_error']is None
assert s['cms_signer_thumbprint']==s['certificate_thumbprint']==hashlib.sha1((W/'private/G59-public.cer').read_bytes()).hexdigest().upper()
assert not s['root_trust_store_changed']and not s['private_key_exported']
pe=pefile.PE(data=data);prior=pefile.PE(data=old)
assert pe.FILE_HEADER.Machine==0xaa64 and pe.OPTIONAL_HEADER.Subsystem==1 and pe.FILE_HEADER.NumberOfSections==prior.FILE_HEADER.NumberOfSections
sections=[]
for x,y in zip(pe.sections,prior.sections):
 assert x.Name==y.Name and x.VirtualAddress==y.VirtualAddress and x.Misc_VirtualSize==y.Misc_VirtualSize and x.Characteristics==y.Characteristics and x.get_data()==y.get_data()
 sections.append({'name':x.Name.rstrip(b'\0').decode(),'raw_bytes':x.SizeOfRawData,'sha256':sha(x.get_data())})
checksum=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');sec=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];secoff=sec.get_file_offset();assert secoff>checksum+4
h=hashlib.sha256();h.update(data[:checksum]);h.update(data[checksum+4:secoff]);h.update(data[secoff+8:pe.OPTIONAL_HEADER.SizeOfHeaders]);cursor=pe.OPTIONAL_HEADER.SizeOfHeaders
for x in sorted(pe.sections,key=lambda x:x.PointerToRawData):
 if not x.SizeOfRawData:continue
 assert x.PointerToRawData==cursor,'Only contiguous generated-image layout accepted'
 h.update(data[cursor:cursor+x.SizeOfRawData]);cursor+=x.SizeOfRawData
assert cursor<=sec.VirtualAddress and sec.VirtualAddress+sec.Size==len(data)
h.update(data[cursor:sec.VirtualAddress]);actual=h.hexdigest()
content=base64.b64decode(s['indirect_content_base64'],validate=True)
def der(buf,at=0):
 tag=buf[at];n=buf[at+1];pos=at+2
 if n&128:
  count=n&127;assert 1<=count<=4;n=int.from_bytes(buf[pos:pos+count],'big');pos+=count
 end=pos+n;assert end<=len(buf);return tag,buf[pos:end],end
def children(buf):
 result=[];at=0
 while at<len(buf):tag,value,at=der(buf,at);result.append((tag,value))
 return result
tag,value,end=der(content);assert tag==0x30 and end==len(content);parts=children(value);assert len(parts)==2 and parts[1][0]==0x30
digestinfo=children(parts[1][1]);assert len(digestinfo)==2 and digestinfo[0][0]==0x30 and digestinfo[1][0]==4 and len(digestinfo[1][1])==32
alg=children(digestinfo[0][1]);assert alg[0]==(6,bytes.fromhex('608648016503040201'))
expected=digestinfo[1][1].hex();assert actual==expected,(actual,expected)
imports={x.dll.decode():[i.name.decode()if i.name else '#%d'%i.ordinal for i in x.imports]for x in pe.DIRECTORY_ENTRY_IMPORT}
assert set(imports)=={'ntoskrnl.exe','WDFLDR.SYS','HAL.dll'}
assert not any(n.startswith(('ZwWriteFile','NtWriteFile'))for names in imports.values()for n in names)
assert 'MmMapIoSpaceEx' in imports['ntoskrnl.exe'] and 'MmUnmapIoSpace' in imports['ntoskrnl.exe']
assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==prior.OPTIONAL_HEADER.AddressOfEntryPoint
report={'signed_driver_sha256':sha(data),'unsigned_driver_sha256':sha(old),'ARM64_native_driver':True,'embedded_CMS_signature_cryptographically_verified_by_Windows':True,'CMS_signer_equals_project_public_certificate':True,'SHA256_Authenticode_digest_matches_verified_CMS_content':True,'Authenticode_digest':actual,'all_loadable_sections_byte_identical_before_after_signing':True,'sections':sections,'imports':imports,'entry_RVA':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'root_trust_store_changed':False,'host_authenticode_policy_status':s['authenticode_policy_status'],'host_authenticode_policy_message':s['authenticode_policy_message'],'certificate_not_before':s['certificate_not_before'],'certificate_not_after':s['certificate_not_after'],'private_key_exported':False,'production_trust_or_WHQL_claimed':False,'limits':['This verifies file/signature integrity, not production certificate-chain trust.','Native code-integrity enforcement without an attached debugger is not established.','No native MMIO or driver loading is performed by this verifier.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['signed_driver_sha256','SHA256_Authenticode_digest_matches_verified_CMS_content','all_loadable_sections_byte_identical_before_after_signing','root_trust_store_changed','host_authenticode_policy_status']}))
