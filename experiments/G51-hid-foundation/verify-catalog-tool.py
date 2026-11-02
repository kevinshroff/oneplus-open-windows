"""Verify pinned SDK tool integrity without changing any certificate trust store."""
from pathlib import Path
import base64,hashlib,json
import pefile
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('catalog-tool-signature.json');P=W/'private/catalog-tools/Inf2Cat.exe';data=P.read_bytes();want='b594728d38b271979367abc8060a971b8e42422738009be126710b1f5dd0fcbc';assert hashlib.sha256(data).hexdigest()==want
ps=r'''
$ErrorActionPreference='Stop';$p='C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G51-catalog-tools\Inf2Cat.exe'
$b=[IO.File]::ReadAllBytes($p);$pe=[BitConverter]::ToInt32($b,0x3c);$opt=$pe+24;$sec=$opt+112+32;$at=[BitConverter]::ToUInt32($b,$sec);$len=[BitConverter]::ToUInt32($b,$at)
$pkcs=New-Object byte[] ($len-8);[Array]::Copy($b,$at+8,$pkcs,0,$pkcs.Length);Add-Type -AssemblyName System.Security;$cms=New-Object Security.Cryptography.Pkcs.SignedCms;$cms.Decode($pkcs);$cms.CheckSignature($true);$auth=Get-AuthenticodeSignature -LiteralPath $p
@{sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower();CMS_cryptographic_signature_verified=$true;signer_subject=$cms.SignerInfos[0].Certificate.Subject;signer_sha256=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cms.SignerInfos[0].Certificate.RawData))).Replace('-','').ToLower();indirect_content_base64=[Convert]::ToBase64String($cms.ContentInfo.Content);Windows_trust_status=[string]$auth.Status;Windows_trust_message=$auth.StatusMessage;trust_store_changed=$false}|ConvertTo-Json -Compress
'''
r=R.op('cryptographic-check','host','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',ps]);assert r['status']=='ok'and r.get('exit_code')==0,r;m=json.loads(r['output']);assert m['sha256']==want and m['CMS_cryptographic_signature_verified']and'Microsoft Corporation'in m['signer_subject']
pe=pefile.PE(data=data);assert pe.FILE_HEADER.Machine==0x8664;checksum=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');sec=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];off=sec.get_file_offset();h=hashlib.sha256();h.update(data[:checksum]);h.update(data[checksum+4:off]);h.update(data[off+8:pe.OPTIONAL_HEADER.SizeOfHeaders]);cursor=pe.OPTIONAL_HEADER.SizeOfHeaders
for s in sorted(pe.sections,key=lambda x:x.PointerToRawData):
 if not s.SizeOfRawData:continue
 assert s.PointerToRawData==cursor;h.update(data[cursor:cursor+s.SizeOfRawData]);cursor+=s.SizeOfRawData
assert cursor<=sec.VirtualAddress and sec.VirtualAddress+sec.Size==len(data);h.update(data[cursor:sec.VirtualAddress]);actual=h.digest()
content=base64.b64decode(m['indirect_content_base64'])
def der(b,at=0):
 tag=b[at];n=b[at+1];p=at+2
 if n&128:k=n&127;assert 1<=k<=4;n=int.from_bytes(b[p:p+k],'big');p+=k
 end=p+n;assert end<=len(b);return tag,b[p:end],end
def children(b):
 out=[];at=0
 while at<len(b):t,v,at=der(b,at);out.append((t,v))
 return out
t,v,end=der(content);assert t==48 and end==len(content);info=children(v);digest=children(info[1][1]);assert digest[1][0]==4 and digest[1][1]==actual
package=W.parent/'spi-G27/private/wdk-packages/microsoft.windows.wdk.arm64.nupkg';assert hashlib.sha256(package.read_bytes()).hexdigest()=='e705b2a63eab891def8f98087666f93e8f21da8e3b5def81a624b83fef5bdae9'
import zipfile
with zipfile.ZipFile(package)as z:assert z.read('c/bin/10.0.26100.0/x86/Inf2Cat.exe')==data
R.s['verification']={'passed':True,'tool_sha256':want,'CMS_signature_and_Authenticode_SHA256_digest_verified':True,'same_bytes_from_pinned_official_WDK_package':True,'signer_subject':m['signer_subject'],'signer_sha256':m['signer_sha256'],'Windows_trust_status':m['Windows_trust_status'],'Windows_trust_message':m['Windows_trust_message'],'trust_store_changed':False,'production_certificate_chain_trust_claimed':False,'REA_metadata_file':'catalog-tool-REA.json','basis_for_execution':'Exact bytes from the existing pinned official Microsoft WDK package, plus matching embedded cryptographic signature/digest; no reliance on an untrusted certificate-chain claim.'};R.persist();print(json.dumps(R.s['verification']))
