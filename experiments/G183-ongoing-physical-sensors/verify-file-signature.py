"""Check the image digest as well as the CMS signature without enrolling trust."""
from pathlib import Path
import struct,hashlib,subprocess,json
w=Path(__file__).resolve().parent;p=w/'private';b=(p/'OpenG183.sys').read_bytes();pe=struct.unpack_from('<I',b,60)[0];op=pe+24
checksum=op+64;secdir=op+112+32;certoff,certbytes=struct.unpack_from('<II',b,secdir);dwlen=struct.unpack_from('<I',b,certoff)[0]
sig=p/'signature.der';sig.write_bytes(b[certoff+8:certoff+dwlen])
def tlv(data,offset=0):
 tag=data[offset];n=data[offset+1];head=2
 if n&128:
  count=n&127;assert 0<count<=4;n=int.from_bytes(data[offset+2:offset+2+count],'big');head+=count
 end=offset+head+n;assert end<=len(data)
 return tag,data[offset+head:end],end
def children(data):
 out=[];at=0
 while at<len(data):
  tag,payload,end=tlv(data,at);out.append((tag,payload,data[at:end]));at=end
 return out
root=children(tlv(sig.read_bytes())[1]);assert root[0][0]==6 and root[1][0]==0xa0
signed=children(tlv(root[1][1])[1]);assert signed[2][0]==0x30
ci=children(signed[2][1]);assert ci[0][0]==6 and ci[1][0]==0xa0
content=ci[1][1];assert tlv(content)[0]==0x30 and tlv(content)[2]==len(content)
(p/'signed-indirect-data.der').write_bytes(content)
receipt=json.loads((p/'package-build.json').read_text());assert receipt['cms_verified'] and receipt['files']['OpenG183.sys']['sha256']==hashlib.sha256(b).hexdigest()
nsections=struct.unpack_from('<H',b,pe+6)[0];opbytes=struct.unpack_from('<H',b,pe+20)[0];hdrsize=struct.unpack_from('<I',b,op+60)[0]
h=hashlib.sha256();h.update(b[:checksum]);h.update(b[checksum+4:secdir]);h.update(b[secdir+8:hdrsize]);sections=[]
for i in range(nsections):
 off=op+opbytes+40*i;sz,ptr=struct.unpack_from('<II',b,off+16)
 if sz:sections.append((ptr,sz))
end=hdrsize
for ptr,sz in sorted(sections):assert ptr==end and ptr+sz<=certoff;h.update(b[ptr:ptr+sz]);end=ptr+sz
assert end<=certoff;h.update(b[end:certoff]);digest=h.digest()
# The signed SpcIndirectDataContent ends in DigestInfo(SHA256, OCTET STRING).
content=(p/'signed-indirect-data.der').read_bytes();suffix=bytes.fromhex('3031300d060960864801650304020105000420')+digest
assert content.endswith(suffix),(digest.hex(),content[-51:].hex())
unsigned=(p/'G183-unsigned.sys').read_bytes();assert unsigned[:checksum]==b[:checksum] and unsigned[checksum+4:secdir]==b[checksum+4:secdir] and unsigned[secdir+8:]==b[secdir+8:len(unsigned)]
v={'CMS_signature_verified_by_native_SignedCms':True,'signed_image_SHA256_matches':True,'authenticode_image_digest':digest.hex(),'certificate_thumbprint':'0000000000000000000000000000000000000000','native_laptop_trust':'self-signed project root is not enrolled on laptop; expected untrusted-root policy failure','file_signature_mismatch':False,'trust_store_changes':0,'phone_policy_qualification':'pending native phone load','signed_driver_sha256':hashlib.sha256(b).hexdigest()}
(w/'file-signature-verification.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
