"""Decode only fully captured command-database entries and opaque aux bytes."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--inventory',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
p.add_argument('--raw-output',type=Path)
a=p.parse_args();assert not a.output.exists()
j=json.loads(a.inventory.read_text());w=j['cmd_db_dwords'];assert len(w)==1536
b=struct.pack('<1536I',*w);assert struct.unpack_from('<II',b)==(1,0x0c0330db)
fixed=144;entries=[]
for n in range(8):
    sid,hoff,doff,count,version,r0,r1,r2=struct.unpack_from('<8H',b,8+n*16)
    if not sid:assert count==0;continue
    assert r0==r1==r2==0 and fixed+hoff+count*24<=len(b)
    for i in range(count):
        rawid,p0,p1,address,length,offset=struct.unpack_from('<8sIIIHH',b,fixed+hoff+i*24)
        end=fixed+doff+offset+length;assert end<=len(b)
        key=rawid.rstrip(b'\0').decode('ascii');assert key
        entries.append(dict(id=key,slave_id=sid,version=hex(version),address=hex(address),aux_hex=b[fixed+doff+offset:end].hex()))
assert len(entries)==175
out=dict(source_sha256=hashlib.sha256(b).hexdigest(),bytes_captured=len(b),header_version=1,all_entry_and_aux_bounds_passed=True,entries=entries)
a.output.write_text(json.dumps(out,indent=2)+'\n')
if a.raw_output:
    assert not a.raw_output.exists();a.raw_output.write_bytes(b)
print('decoded',len(entries),'entries; auxiliary bytes remain opaque')
