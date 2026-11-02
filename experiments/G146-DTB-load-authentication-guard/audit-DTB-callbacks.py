"""Bind the compiled copy/hash callbacks and crypto dispatch dependency."""
from pathlib import Path
from importlib.machinery import SourceFileLoader
import ast,hashlib,json,struct,uuid
import pefile
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(p/'BdsDxe-linked.efi').read_bytes();pe=pefile.PE(data=raw)
symbols=json.loads((p/'linked-symbols-all.json').read_text())
proof={name:json.loads((p/('linked-'+name+'-REA.json')).read_text())for name in ['AuthorizeCopy','VerifyPayload']}
for name,symbol in [('AuthorizeCopy','AuthorizeDtbCopy'),('VerifyPayload','VerifyDtbPayload')]:
 r=proof[name];body=r['normalized_result']['procedure']['body']
 assert r['subject']['digest']['sha256']==sha(raw)and body['available']and not body['non_contiguous']
 assert int(r['normalized_result']['procedure']['address'],16)==symbols[symbol]['RVA']and body['total_bytes']==symbols[symbol]['bytes']
copy=proof['AuthorizeCopy']['normalized_result']['instructions'];payload=proof['VerifyPayload']['normalized_result']['instructions']
check=f"bl 0x{symbols['Check']['RVA']:08x}"
assert sum(x.endswith(check)for x in copy)==1 and sum(x.endswith(check)for x in payload)==2
assert any(x.endswith('mov x0, xzr')for x in copy)
assert any(x.endswith('mov w0, #0x1')for x in payload)and any(x.endswith('mov w0, #0x2')for x in payload)
hash_call=[i for i,x in enumerate(payload)if x.endswith('blr x8')];assert len(hash_call)==1
assert [x.split(': ',1)[1]for x in payload[hash_call[0]-2:hash_call[0]+1]]==['mov w0, #0x9e980000','mov w1, #0x20b8','blr x8']
expected='f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94'
assert pe.get_data(0x65320,32)==bytes.fromhex(expected)
assert any(x.endswith('add x1, x1, #0x320')for x in payload)and any(x.endswith('mov w2, #0x20')for x in payload)
m=SourceFileLoader('g106inventory',str(w.parent/'charging-G106/inventory-fd.py')).load_module()
s=(w.parent/'charging-G144/audit-image.py').read_text();cls=next(n for n in ast.parse(s).body if isinstance(n,ast.ClassDef)and n.name=='Extract');env={'m':m,'struct':struct};exec(compile(ast.Module(body=[cls],type_ignores=[]),'<extractor>','exec'),env)
fd=env['Extract']();fd.volume((p/'G146-dtb-auth.fd').read_bytes());bds=fd.raw['6d33944a-ec75-4855-a54d-809c75241f6c']
at=32 if bds[20:23]==b'\xff\xff\xff'else 24;depex=[]
while at<len(bds):
 n=int.from_bytes(bds[at:at+3],'little');head=4
 if n==0xffffff:n=struct.unpack_from('<I',bds,at+4)[0];head=8
 if bds[at+3]==0x13:depex.append(bds[at+head:at+n])
 at=min((at+n+3)&~3,len(bds))
assert depex==[(p/'BdsDxe.depex').read_bytes()]
crypto=uuid.UUID('2c2275c9-3a7b-426f-be54-2d22bd9d1092').bytes_le
pos=0;stack=[];guids=[]
while pos<len(depex[0]):
 op=depex[0][pos];pos+=1
 if op==2:
  g=depex[0][pos:pos+16];assert len(g)==16;pos+=16;guids.append(g);stack.append(g!=crypto)
 elif op==3:assert len(stack)>=2;v=stack.pop();stack[-1]=stack[-1]and v
 else:assert op==8 and pos==len(depex[0])and len(stack)==1
assert crypto in guids and stack==[False]
result={'passed':True,'BDS_sha256':sha(raw),'FD_sha256':sha((p/'G146-dtb-auth.fd').read_bytes()),'REA_evidence_ids':[proof[n]['evidence_id']for n in proof],'copy_check_index':0,'payload_check_indices':[1,2],'compiled_hash_target':'9E980000','compiled_hash_bytes':8376,'compiled_expected_SHA256':expected,'compiled_crypto_protocol_dependency_required':True,'compiled_depex_sha256':sha(depex[0]),'native_G146_boots':0,'limits':['Static compiled callbacks, fixed hash arguments and dispatch dependency; not native hash completion.','Crypto library constructor checks protocol presence/version. Hash service may return failure, which denies AUTH.','Source-model ownership/display/CPU checks remain finite, not global DMA or production power qualification.']}
(p/'DTB-callback-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
