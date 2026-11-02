"""Seed only observed indirect callback addresses via analysis-only ELF symbols.
No original code/data byte changes, native load, or inferred live binding.
"""
from pathlib import Path
import hashlib,json,struct
w=Path(__file__).resolve().parent;p=w/'private';src=p/'views-03/Preprocess.elf';out=p/'FVEventStates.elf';assert not out.exists()
raw=src.read_bytes();assert hashlib.sha256(raw).hexdigest()=='9f64e6e255be2b6e41782fe97a54a5ff6de7d879c498a55c6326f2b44bcaa2cb'
b=bytearray(raw);h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b));rows=[struct.unpack_from('<8I',b,h[5]+32*i)for i in range(h[10])]
seeds={0x601736d0:'state1',0x6018e910:'state11',0x60191320:'state13',0x6018fc60:'sub11_screening',0x601928e0:'sub13_screening',0x601729f0:'common_screening'}
names=bytearray(b'\0');strings=bytearray(b'\0');syms=bytearray(16);sections=[(0,)*10]
def n(s):
 off=len(names);names.extend(s.encode()+b'\0');return off
for i,r in enumerate(rows):sections.append((n('.load'+str(i)),1,2|((r[6]&1)*4)|((r[6]&2)//2),r[2],r[1],r[4],0,0,4,0))
for addr,name in seeds.items():
 hits=[i for i,r in enumerate(rows)if r[2]<=addr<r[2]+r[4]];assert len(hits)==1
 off=len(strings);strings.extend(('analyst_'+name).encode()+b'\0');syms.extend(struct.pack('<IIIBBH',off,addr,0,0x12,0,hits[0]+1))
def append(data):
 b.extend(bytes((-len(b))%4));at=len(b);b.extend(data);return at
strindex=len(sections);at=append(strings);sections.append((n('.strtab'),3,0,0,at,len(strings),0,0,1,0))
at=append(syms);sections.append((n('.symtab'),2,0,0,at,len(syms),strindex,1,4,16))
shstr=len(sections);nameoff=n('.shstrtab');at=append(names);sections.append((nameoff,3,0,0,at,len(names),0,0,1,0))
b.extend(bytes((-len(b))%4));h[6]=len(b);h[11]=40;h[12]=len(sections);h[13]=shstr
for s in sections:b.extend(struct.pack('<10I',*s))
struct.pack_into('<16sHHIIIIIHHHHHH',b,0,*h)
for r in rows:assert b[r[1]:r[1]+r[4]]==raw[r[1]:r[1]+r[4]]
out.write_bytes(b);(p/'seed-metadata.json').write_text(json.dumps({'parent':str(src),'parent_sha256':hashlib.sha256(raw).hexdigest(),'view_sha256':hashlib.sha256(b).hexdigest(),'all_load_segment_bytes_unchanged':True,'analyst_function_seeds':{hex(k):v for k,v in seeds.items()},'origin':'Original constructors601732f0/6018e4d0/60190e60 and their stored callback pointers; common screening constructor601727c0. Analyst names are not original symbols.','limits':['Names/section table are synthetic analysis metadata. Not a native executable or evidence of actual current state.']},indent=2)+'\n');print(hashlib.sha256(b).hexdigest())
