"""Bind the combined image's serial ABI to REA bytes and six leaf replays and both inlined/out-of-line translation helpers."""
from pathlib import Path
import hashlib,json,re,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_LR,UC_ARM64_REG_SP
w=Path(__file__).resolve().parent/'private'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
pe=pefile.PE(data=(w/'BdsDxe-linked.efi').read_bytes())
def symbol(path,name):
 lines=path.read_text().splitlines();matches=[]
 for i,line in enumerate(lines):
  m=re.fullmatch(r'([0-9a-fA-F]+) 00000000\s+0\s+'+re.escape(name),line)
  if m:matches.append((int(m[1],16),i))
 assert len(matches)==1,(name,matches)
 addr,i=matches[0];prior=re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+)\s+',lines[i-1])
 size=int(prior[2],16) if prior and int(prior[1],16)==addr else None
 return addr,size
mp=w/'BdsDxe-linked.map'
symbols={n:symbol(mp,n)[0] for n in ['Forward','SerialWrite','SerialPoll','SerialRead','mSerialProxy']}
def proof(name):
 r=json.loads((w/('linked-'+name+'-REA.json')).read_text())
 assert r['subject']['digest']['sha256']==sha(w/'BdsDxe-linked.efi')
 return r
proxy=proof('proxy');d=proxy['normalized_result'];raw=bytes.fromhex(d['bytes_hex'])
assert d['complete'] and int(d['address'],16)==symbols['mSerialProxy']
assert struct.unpack('<7Q',raw)==(0,0,symbols['SerialWrite'],0,0,symbols['SerialPoll'],symbols['SerialRead'])
assert pe.get_data(symbols['mSerialProxy'],56)==raw
relocs={r.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for r in b.entries if r.type==10}
assert {symbols['mSerialProxy']+n for n in [16,40,48]}<=relocs
leaves=proof('leaves');d=leaves['normalized_result'];raw=bytes.fromhex(d['bytes_hex'])
assert d['complete'] and pe.get_data(symbols['SerialPoll'],64)==raw
assert symbols['SerialRead']==symbols['SerialPoll']+32
rows=[];counter=None
for name in ['SerialPoll','SerialRead']:
 for before in [0,1,0xffffffff]:
  base,stop=0x10000000,0x90010000;u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
  image=pe.get_memory_mapped_image();u.mem_map(base,(len(image)+4095)&~4095);u.mem_write(base,image)
  u.mem_map(0x90000000,0x20000)
  if counter is not None:u.mem_write(base+counter,struct.pack('<I',before))
  u.reg_write(UC_ARM64_REG_X0,0xdead0000);u.reg_write(UC_ARM64_REG_X1,0xffffffffffffffff)
  u.reg_write(UC_ARM64_REG_LR,stop);u.reg_write(UC_ARM64_REG_SP,0x90008000)
  writes=[];u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,kind,at,n,value,data:writes.append((at,n,value)))
  u.emu_start(base+symbols[name],stop,count=32)
  assert u.reg_read(UC_ARM64_REG_X0)==0 and u.reg_read(UC_ARM64_REG_X1)==0xffffffffffffffff
  if counter is None:
   assert before==0 and len(writes)==1 and writes[0][1:]==(4,1)
   counter=writes[0][0]-base
   assert any(s.Characteristics&0x80000000 and s.VirtualAddress<=counter<counter+4<=s.VirtualAddress+s.Misc_VirtualSize for s in pe.sections)
  after=struct.unpack('<I',u.mem_read(base+counter,4))[0]
  assert after==min(before+1,0xffffffff)
  assert writes==([] if before==0xffffffff else [(base+counter,4,after)])
  rows.append({'function':name,'RVA':symbols[name],'counter_before':before,'counter_after':after,'caller_buffer_unmapped':True,'writes':len(writes)})
forward=proof('Forward')['normalized_result']['instructions'];write=proof('SerialWrite')['normalized_result']['instructions']
assert forward[:5]==[
 f"0x{symbols['Forward']:x}: stp x19, x20, [sp, #-0x30]!",
 f"0x{symbols['Forward']+4:x}: str x21, [sp, #0x10]",
 f"0x{symbols['Forward']+8:x}: stp x29, x30, [sp, #0x18]",
 f"0x{symbols['Forward']+12:x}: add x29, sp, #0x18",
 f"0x{symbols['Forward']+16:x}: strb wzr, [x29, #0x17]"]
idx=[i for i,s in enumerate(forward) if ': blr ' in s];assert len(idx)==1
argument_writes=[s for s in forward[:idx[0]] if re.search(r': (mov|ldr|ldp|add|sub|and|orr|csel|cset|eor|adrp|adr|ubfx|sxtw) [wx][0-4](?:,| )',s)]
assert len(argument_writes)==1 and argument_writes[0].endswith('mov x4, x19')
assert any(s.endswith('mov x19, x4') for s in forward[:idx[0]])
assert any(s.endswith('mov x19, x1') for s in write[:10]) and any(s.endswith('mov x20, x0') for s in write[:10])
assert any(s.endswith('sub x8, x19, #0x201') for s in write[:30])
inline=json.loads((w/'inline-AT-audit.json').read_text())
assert inline['passed'] and inline['BDS_sha256']==sha(w/'BdsDxe-linked.efi') and inline['linked_AT_sequences']==24
assert inline['all_executable_AT_opcode_occurrences_covered'] and inline['PAR_DAIF_saved_and_restored_with_independent_registers']
report={'passed':True,'BDS_sha256':sha(w/'BdsDxe-linked.efi'),'link_map_sha256':sha(mp),
 'REA_snapshot_sha256':sha(w/'linked-main.rea.json'),'symbols_from_linker_map':symbols,
 'serial_proxy_DIR64_relocations':True,'Forward_frame_bytes':48,'Forward_anchor_from_SP':47,
 'all_five_original_API_arguments_preserved_before_single_indirect_call':True,
 'SerialWrite_ABI':'X0 buffer, X1 length; bounded length guard retained',
 'inlined_AT_proof':{'report':'inline-AT-audit.json','sequences':24,'source_sha256':inline['helper_source_unchanged_sha256'],'source_unchanged':True,'selector_counts':inline['selector_counts']},
 'actual_linked_Read_Poll_cases':6,'leaf_counter_RVA':counter,'leaf_model_results':rows,
 'native_phone_operations':0,'native_G151_boots':0,
 'limits':['Linker names are build metadata, not recovered PDB symbols.','The instruction replay models RAM/register inputs; no native secure call or CPU translation instruction executes.','Source/model/static ABI checks do not establish native restore success, hardware ownership or DSP startup.']}
(w/'linked-sink-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['leaf_model_results','limits']},indent=2))
