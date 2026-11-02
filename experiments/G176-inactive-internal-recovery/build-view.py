"""Add observed procedure entry seeds to the complete exact-byte Battery PD view.
Only analysis metadata changes. The artifact is never deployed or executed.
"""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
raw=a.input.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)=='309595a2e074374d6d2d564d727735614a08325193a52e88418ebddacb831fbe'
b=bytearray(raw);h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b));rows=[struct.unpack_from('<8I',b,h[5]+32*i)for i in range(h[10])];assert len(rows)==5
seeds={0x6002b730:'platform_selector',0x6005a400:'platform4_property_get',0x6009e110:'array_read_boundary',0x6009a6d0:'technology_R2_get',0x600d6960:'model47_R2_status',0x600d8580:'SCHG_initializer',0x601c26e0:'property_router',0x601736d0:'state1',0x6018e910:'state11',0x60191320:'state13',0x6018fc60:'sub11_screening',0x601928e0:'sub13_screening',0x601729f0:'common_screening'}
names=bytearray(b'\0');strings=bytearray(b'\0');symbols=bytearray(16);sections=[(0,)*10]
def name(s):at=len(names);names.extend(s.encode()+b'\0');return at
for i,r in enumerate(rows):sections.append((name('.load'+str(i)),1,2|((r[6]&1)*4)|((r[6]&2)//2),r[2],r[1],r[4],0,0,4,0))
for address,label in seeds.items():
 matching=[i for i,r in enumerate(rows)if r[2]<=address<r[2]+r[4]];assert len(matching)==1
 off=len(strings);strings.extend(('analyst_'+label).encode()+b'\0');symbols.extend(struct.pack('<IIIBBH',off,address,0,0x12,0,matching[0]+1))
def append(data):b.extend(bytes((-len(b))%4));off=len(b);b.extend(data);return off
string_index=len(sections);off=append(strings);sections.append((name('.strtab'),3,0,0,off,len(strings),0,0,1,0))
off=append(symbols);sections.append((name('.symtab'),2,0,0,off,len(symbols),string_index,1,4,16))
name_index=len(sections);name_off=name('.shstrtab');off=append(names);sections.append((name_off,3,0,0,off,len(names),0,0,1,0))
b.extend(bytes((-len(b))%4));h[6]=len(b);h[11]=40;h[12]=len(sections);h[13]=name_index
for row in sections:b.extend(struct.pack('<10I',*row))
struct.pack_into('<16sHHIIIIIHHHHHH',b,0,*h)
for r in rows:assert b[r[1]:r[1]+r[4]]==raw[r[1]:r[1]+r[4]]
a.output.mkdir(parents=True,exist_ok=False);(a.output/'BatteryStatusConsumers.elf').write_bytes(b)
proof={'source_view_sha256':sha(raw),'view_sha256':sha(b),'all_load_segment_bytes_unchanged':True,'seeds':{hex(k):v for k,v in seeds.items()},'seed_origins':['G175 recovered model47 table/initializer and its actual READ helper call.','Prior REA dossiers for platform selector/property getter/router/technology status pass-through.','G168 observed constructor-stored FSM callbacks; no new guessed code entry.'],'limits':['Analyst symbol names are not original names. Entry seeds do not prove live callback selection.','Uninitialized tails are not observed live memory. No physical read or native code change.']}
(a.output/'proof.json').write_text(json.dumps(proof,indent=2)+'\n');print({'sha256':sha(b),'bytes':len(b),'seeds':len(seeds),'native_operations':0})
