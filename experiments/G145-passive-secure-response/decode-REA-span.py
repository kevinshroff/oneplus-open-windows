"""Decode a complete original-byte REA span with LLVM using a synthetic section.

The original ELF has no section headers. The derivative has no PT_LOAD records
and is only a disassembly container. No original byte or native state changes.
"""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--proof',required=True,type=Path)
p.add_argument('--tz',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();a.output.mkdir(exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
original=a.tz.read_bytes();proof=json.loads(a.proof.read_text());d=proof['normalized_result']
assert sha(original)=='dbd1e8e09fd6aca142755989b3ce97b5a271dec3432a572a01167849be83ae80'
assert proof['subject']['digest']['sha256']==sha(original) and d['complete']
base=int(d['address'],16);data=bytes.fromhex(d['bytes_hex']);assert len(data)==d['requested_bytes']==d['returned_bytes']
h=struct.unpack_from('<16sHHIQQQIHHHHHH',original);segments=[]
for i in range(h[10]):
 typ,flags,off,va,pa,size,mem,align=struct.unpack_from('<IIQQQQQQ',original,h[5]+i*h[9])
 if typ==1 and va<=base and base+len(data)<=va+size:segments.append((i,off+base-va))
assert len(segments)==1 and original[segments[0][1]:segments[0][1]+len(data)]==data
names=bytes(1)+b'.text'+bytes(1)+b'.shstrtab'+bytes(1)
nameoff=64+len(data);shoff=(nameoff+len(names)+7)&~7
header=struct.pack('<16sHHIQQQIHHHHHH',bytes.fromhex('7f454c46020101')+bytes(9),2,183,1,base,0,shoff,0,64,0,0,64,3,2)
image=header+data+names+bytes(shoff-(nameoff+len(names)))+bytes(64)
image+=struct.pack('<IIQQQQIIQQ',1,1,6,base,64,len(data),0,0,4,0)
image+=struct.pack('<IIQQQQIIQQ',7,3,0,0,nameoff,len(names),0,0,1,0)
elf=a.output/'inspection.elf';elf.write_bytes(image)
objdump=subprocess.check_output(['xcrun','--find','llvm-objdump'],text=True).strip()
r=subprocess.run([objdump,'-d','--disassemble-zeroes','--print-imm-hex','--no-show-raw-insn',str(elf.resolve())],capture_output=True,text=True)
assert r.returncode==0,r.stderr
(a.output/'LLVM.txt').write_text(r.stdout)
info={'source_TZ_sha256':sha(original),'REA_evidence_id':proof['evidence_id'],
 'original_ELF_section_count':h[12],'source_PT_LOAD_segment':segments[0][0],
 'source_file_offset':segments[0][1],'virtual_base':hex(base),'bytes':len(data),
 'bytes_sha256':sha(data),'derived_ELF_sha256':sha(image),
 'decoder_source_sha256':sha(Path(__file__).read_bytes()),
 'LLVM_version':subprocess.check_output([objdump,'--version'],text=True).splitlines()[0],
 'scope':'Derived disassembly; exact REA/source bytes, synthetic section metadata. Not native execution.',
 'native_operations':0}
(a.output/'mapping-proof.json').write_text(json.dumps(info,indent=2)+'\n')
print(json.dumps(info,indent=2))
