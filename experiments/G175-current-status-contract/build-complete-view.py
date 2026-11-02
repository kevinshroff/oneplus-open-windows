"""Include the Battery PD's later read-only/TLS segments in an exact-byte REA view.

This modifies only an analysis container. It is never deployed or executed.
Uninitialized tails remain BSS, not observations of live DSP memory.
"""
from pathlib import Path
import argparse,hashlib,json,struct
a=argparse.ArgumentParser();a.add_argument('--input',type=Path,required=True);a.add_argument('--output',type=Path,required=True);arg=a.parse_args()
b=arg.input.read_bytes();sha=lambda x:hashlib.sha256(x).hexdigest()
assert sha(b)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b));assert h[0][:7]==b'\x7fELF\x01\x01\x01'and h[9]==32 and h[10]==59
rows=[struct.unpack_from('<8I',b,h[5]+32*i)for i in range(h[10])]
indices=[18,19,20,21,22];expected=[0x60000000,0x602a3000,0x603ab000,0x603ac000,0xe0d4f000]
assert not arg.output.exists();arg.output.mkdir(parents=True)
out=bytearray(4096);notes=[]
for i,(idx,va)in enumerate(zip(indices,expected)):
 r=rows[idx];assert r[0]==1 and r[2]==va and r[4]<=r[5]and r[1]+r[4]<=len(b)
 data=b[r[1]:r[1]+r[4]];out.extend(bytes((-len(out))%4096));off=len(out);out.extend(data)
 struct.pack_into('<8I',out,52+32*i,1,off,r[2],r[3],r[4],r[5],r[6]&7,4096)
 notes.append({'parent_index':idx,'virtual':hex(r[2]),'physical':hex(r[3]),'file_bytes':r[4],'memory_bytes':r[5],'parent_file_offset':r[1],'view_file_offset':off,'source_sha256':sha(data),'BSS_bytes':r[5]-r[4]})
header=h.copy();header[4]=0x60171e70;header[5]=52;header[10]=len(indices);header[6]=header[11]=header[12]=header[13]=0
struct.pack_into('<16sHHIIIIIHHHHHH',out,0,*header)
for row in notes:
 off=row['view_file_offset'];n=row['file_bytes'];assert sha(out[off:off+n])==row['source_sha256']
path=arg.output/'BatteryComplete.elf';path.write_bytes(out)
proof={'parent_sha256':sha(b),'view_sha256':sha(out),'entry_seed':'0x60171e70','regions':notes,'all_original_PT_LOAD_bytes_equal':True,'purpose':'Restore omitted original TLS/read-only segments20/21 and associated22; observe static registration/callback candidates.','limits':['Only ELF analysis headers/file offsets and vendor flag masking differ; original loaded file bytes are exact.','Uninitialized memory is not a live RAM capture.','Other protection domains remain omitted. Static candidate tables do not alone prove native handler selection.','Native CPU permission after DSP authentication is not established by pre-auth loader checks; no DSP RAM read is authorized by this proof.']}
(arg.output/'proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({'view':str(path),'sha256':sha(out),'segments':len(indices),'bytes':len(out),'native_operations':0},indent=2))
