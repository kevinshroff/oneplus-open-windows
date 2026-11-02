"""Reconstruct exact retained DSP bytes for offline REA; never uploads firmware."""
from pathlib import Path
import argparse,hashlib,json,re,struct
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--pins',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
pins={}
for name,n,h in re.findall(r'\{"([^"]+)", (\d+)ULL, \{([^}]+)\}\}',a.pins.read_text()):pins[name]=(int(n),bytes(int(x.strip(),16)for x in h.split(',')).hex())
assert len(pins)==64
for name,(n,h)in pins.items():
 b=(a.inputs/name).read_bytes();assert len(b)==n and sha(b)==h,name
mdt=(a.inputs/'adsp.mdt').read_bytes();h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',mdt));assert h[0][:7]==b'\x7fELF\x01\x01\x01'and h[2]==164 and h[9]==32 and h[10]==59
rows=[list(struct.unpack_from('<8I',mdt,h[5]+i*h[9]))for i in range(h[10])];full=bytearray(max(r[1]+r[4]for r in rows));assert len(full)<80<<20
occupied=[]
for i,r in enumerate(rows):
 if not r[4]:continue
 b=(a.inputs/('adsp.b%02d'%i)).read_bytes();assert len(b)==r[4]
 for at,n in occupied:assert r[1]+len(b)<=at or at+n<=r[1]
 full[r[1]:r[1]+len(b)]=b;occupied.append((r[1],len(b)))
assert full[:1940]==mdt[:1940]
(a.output/'adsp-analysis.elf').write_bytes(full)
subset=bytearray(4096);selected=[18,19,20,21,22];notes=[]
for index,i in enumerate(selected):
 r=rows[i].copy();data=full[r[1]:r[1]+r[4]];r[1]=len(subset);subset.extend(data);subset.extend(bytes((-len(subset))&4095));struct.pack_into('<8I',subset,52+index*32,*r);notes.append({'original_segment':i,'virtual':hex(r[2]),'filesz':r[4],'memsz':r[5],'payload_sha256':sha(data)})
h[4]=rows[18][2];h[5]=52;h[10]=len(selected);struct.pack_into('<16sHHIIIIIHHHHHH',subset,0,*h)
(a.output/'battery-module-analysis.elf').write_bytes(subset)
r={'all_64_pinned_files_match':True,'full_sha256':sha(full),'subset_sha256':sha(subset),'segments':notes,'analysis_entry':hex(h[4]),'native_operations':0,'limits':['Offline views only. Gaps are zero reconstruction; subset headers/file offsets/entry seed are analyst choices. Exact payload bytes and virtual addresses are preserved. Dependencies outside selected segments are omitted.','No replacement firmware, secure request, runtime ownership claim or dynamic Hexagon emulation.']};(a.output/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
