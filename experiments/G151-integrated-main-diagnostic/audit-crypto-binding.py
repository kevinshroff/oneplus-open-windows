"""Bind DTB SHA arguments, exact crypto version and required FD dependency.

Static compiled evidence only; no provider installation, hash-service completion,
native constructor return or hardware ownership is established.
"""
from pathlib import Path
from importlib.machinery import SourceFileLoader
import ast,hashlib,json,struct,uuid
import pefile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(p/'BdsDxe-linked.efi').read_bytes();pe=pefile.PE(data=raw);symbols=json.loads((p/'linked-symbols-all.json').read_text())
proof={n:json.loads((p/('linked-'+n+'-REA.json')).read_text())for n in ['Entry','AuthorizeDtbCopy','VerifyDtbPayload']}
for name,symbol in [('Entry','_ModuleEntryPoint'),('AuthorizeDtbCopy','AuthorizeDtbCopy'),('VerifyDtbPayload','VerifyDtbPayload')]:
 d=proof[name];body=d['normalized_result']['procedure']['body'];assert d['subject']['digest']['sha256']==sha(raw)
 assert body['available']and not body['non_contiguous']and body['total_bytes']==symbols[symbol]['bytes']
 assert int(d['normalized_result']['procedure']['address'],16)==symbols[symbol]['RVA']
ins=lambda n:[v.split(': ',1)[1]for v in proof[n]['normalized_result']['instructions']]
copy,payload,entry=ins('AuthorizeDtbCopy'),ins('VerifyDtbPayload'),ins('Entry')
check='bl 0x%08x'%symbols['Check']['RVA'];assert copy.count(check)==1 and payload.count(check)==2
assert 'mov x0, xzr'in copy or'mov w0, wzr'in copy
assert 'mov w0, #0x1'in payload and'mov w0, #0x2'in payload
calls=[i for i,v in enumerate(payload)if v=='blr x8'];assert len(calls)==1
i=calls[0];assert payload[i-2:i+1]==['mov w0, #0x9e980000','mov w1, #0x20b8','blr x8']
assert 'ldr x8, [x8, #0x1e0]'in payload # Crypto protocol SHA256HashAll slot.
expected=bytes.fromhex('f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94')
assert pe.get_data(symbols['mExpectedDigest']['RVA'],32)==expected
assert 'mov w2, #0x20'in payload and'add x1, x1, #0x598'in payload
crypto=uuid.UUID('2c2275c9-3a7b-426f-be54-2d22bd9d1092').bytes_le
assert pe.get_data(symbols['gEdkiiCryptoProtocolGuid']['RVA'],16)==crypto
# The exact constructor version branch is material: newer versions are not
# automatically accepted by this build. Failure paths contain debug assertions.
at=entry.index('cmp x0, #0x13');assert entry[at-2:at+2]==['ldr x8, [x8]','blr x8','cmp x0, #0x13','b.eq 0x000015b4']
assert entry[entry.index('tbnz x0, #0x3f, 0x000014f8')+1]=='ldr x8, [x19]'
assert 'cbz x8, 0x000014f8'in entry and'str xzr, [x21, #0xf0]'in entry
assert 'add x20, x20, #0x3f0'in entry and'add x19, x19, #0xf0'in entry
m=SourceFileLoader('g106inventory',str(w.parent/'charging-G106/inventory-fd.py')).load_module()
s=(w.parent/'charging-G144/audit-image.py').read_text();cls=next(n for n in ast.parse(s).body if isinstance(n,ast.ClassDef)and n.name=='Extract');env={'m':m,'struct':struct};exec(compile(ast.Module(body=[cls],type_ignores=[]),'<extractor>','exec'),env)
fd=env['Extract']();fd.volume((p/'G151-main-auth.fd').read_bytes());bds=fd.raw['6d33944a-ec75-4855-a54d-809c75241f6c']
at=32 if bds[20:23]==b'\xff\xff\xff'else 24;depex=[]
while at<len(bds):
 n=int.from_bytes(bds[at:at+3],'little');head=4
 if n==0xffffff:n=struct.unpack_from('<I',bds,at+4)[0];head=8
 if bds[at+3]==0x13:depex.append(bds[at+head:at+n])
 at=min((at+n+3)&~3,len(bds))
assert len(depex)==1;pos=0;stack=[];guids=[]
while pos<len(depex[0]):
 op=depex[0][pos];pos+=1
 if op==2:
  g=depex[0][pos:pos+16];assert len(g)==16;pos+=16;guids.append(g);stack.append(g!=crypto)
 elif op==3:assert len(stack)>=2;v=stack.pop();stack[-1]=stack[-1]and v
 else:assert op==8 and pos==len(depex[0])and len(stack)==1
assert crypto in guids and stack==[False]
report={'passed':True,'BDS_sha256':sha(raw),'FD_sha256':sha((p/'G151-main-auth.fd').read_bytes()),'REA_evidence_ids':[d['evidence_id']for d in proof.values()],'required_crypto_GUID':'2c2275c9-3a7b-426f-be54-2d22bd9d1092','compiled_dispatch_requires_crypto_protocol':True,'constructor_required_version_exact':19,'constructor_accepts_arbitrary_newer_version':False,'compiled_DTBSHA256_slot':'0x1e0','DTB_hash_address':'0x9e980000','DTB_hash_bytes':8376,'DTB_hash_expected':expected.hex(),'DTB_check_indices':[0,1,2],'DEPEX_sha256':sha(depex[0]),'native_operations':0,'limits':['Static consumer and FD dependency binding; no native provider installation/version or hash completion is observed.','Unsupported/missing interfaces traverse debug assertion paths that may stop native execution. Graceful constructor return is not claimed.','The main verifier uses the unchanged scalar streaming SHA; neither that source nor the native image is rebuilt here.','No native DTB/main/DSP/GLINK/charging or hardware ownership qualification.']}
(p/'crypto-binding-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
