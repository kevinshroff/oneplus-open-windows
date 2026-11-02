"""Bind inlined AT sequences to REA bodies and independently decoded selectors."""
from pathlib import Path
import collections,hashlib,json,re,struct,subprocess
import pefile
w=Path(__file__).resolve().parent;p=w/'private'
sha=lambda b:hashlib.sha256(b).hexdigest()
raw=(p/'BdsDxe-linked.efi').read_bytes();digest=sha(raw);pe=pefile.PE(data=raw)
assert pe.OPTIONAL_HEADER.ImageBase==0
tool=subprocess.check_output(['xcrun','--find','llvm-objdump'],text=True).strip()
version=subprocess.check_output([tool,'--version'],text=True).splitlines()[0]
r=subprocess.run([tool,'-d','--no-show-raw-insn',str(p/'BdsDxe-linked.efi')],capture_output=True,text=True)
assert r.returncode==0,r.stderr
(p/'llvm-disassembly.txt').write_text(r.stdout)
llvm={}
for line in r.stdout.splitlines():
 m=re.match(r'^\s*([0-9a-fA-F]+):\s+(.+)$',line)
 if m:llvm[int(m[1],16)]=m[2].strip().lower()
records=[];evidence=[];bases={}
for label in ['AT-inventory','AT-guard']:
 d=json.loads((p/('linked-'+label+'-REA.json')).read_text())
 assert d['subject']['digest']['sha256']==digest
 n=d['normalized_result'];body=n['procedure']['body']
 assert body['available'] and not body['non_contiguous']
 lines=[]
 for line in n['instructions']:
  m=re.fullmatch(r'0x([0-9a-f]+): (.*)',line);assert m,line
  lines.append((int(m[1],16),m[2].strip().lower()))
 assert len(lines)*4==body['total_bytes']
 evidence.append(d['evidence_id'])
 for i,(address,asm) in enumerate(lines):
  if not asm.startswith('at '):continue
  seq=lines[i-3:i+6];assert len(seq)==9 and all(seq[k+1][0]==seq[k][0]+4 for k in range(8))
  s=[text for _,text in seq]
  mask=re.fullmatch(r'mrs (x\d+), daif',s[0]);prior=re.fullmatch(r'mrs (x\d+), par_el1',s[2]);new=re.fullmatch(r'mrs (x\d+), par_el1',s[5])
  assert mask and prior and new and s[1]=='msr daifset, #0x2' and s[4]=='isb' and s[8]=='isb'
  mask,prior,new=mask[1],prior[1],new[1]
  decoded=re.fullmatch(r'at\s+(s1e[12][rw]),\s*(x\d+)',llvm[address]);assert decoded,llvm[address]
  selector,operand=decoded.groups();assert s[6]=='msr par_el1, '+prior and s[7]=='msr daif, '+mask
  assert len({mask,prior,new,operand})==4
  word=struct.unpack('<I',pe.get_data(address,4))[0];base=word&~31
  if selector in bases:assert bases[selector]==base
  bases[selector]=base
  records.append({'RVA':hex(address),'function':label,'selector':selector,'address_register':operand,
                  'mask_register':mask,'prior_PAR_register':prior,'result_register':new,
                  'opcode':hex(word),'instruction_window':[f'0x{a:x}: {t}'for a,t in seq]})
assert len(records)==12 and len(bases)==4
counts=dict(collections.Counter(x['selector'] for x in records));assert set(counts.values())=={3}
found=[]
for section in pe.sections:
 if not section.Characteristics&0x20000000:continue
 data=section.get_data()
 for offset in range(0,len(data)-3,4):
  if struct.unpack_from('<I',data,offset)[0]&~31 in bases.values():found.append(section.VirtualAddress+offset)
assert set(found)=={int(x['RVA'],16)for x in records} and len(found)==12
source=w/'private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib/OpenDspAt.c'
prior=w.parent/'charging-G139/private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib/OpenDspAt.c'
assert source.read_bytes()==prior.read_bytes()
result={'passed':True,'BDS_sha256':digest,'helper_source_unchanged_sha256':sha(source.read_bytes()),
 'compiler_inlined_helper':True,'REA_evidence_ids':evidence,'LLVM_version':version,
 'linked_AT_sequences':12,'selector_counts':counts,'all_executable_AT_opcode_occurrences_covered':True,
 'PAR_DAIF_saved_and_restored_with_independent_registers':True,'source_changed_for_audit':False,
 'native_operations':0,'records':records,
 'limits':['Static compiled instruction and register-flow checks only. AT hardware results and global ownership are not emulated or claimed.',
           'Ghidra omits the selector from its AT display; LLVM decodes the exact same pinned bytes and supplies that field.',
           'The192-byte out-of-line helper no longer exists; source identity does not imply byte-identical compiled layout.']}
(p/'inline-AT-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if k not in ['records','limits']},indent=2))
