"""Make an offline root0-only IORT candidate from the pinned board SID pairs.

This does not install a table or change firmware. Node offsets and lengths stay
fixed; old unused root0 mapping slots become zero padding, preserving references.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

p = argparse.ArgumentParser(description=__doc__)
for n in ['IORT', 'source', 'selector', 'output', 'report']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
assert not a.output.exists() and not a.report.exists()
b = a.IORT.read_bytes()
assert hashlib.sha256(b).hexdigest() == '7e0b0089aaf96fa3ec3f82d8cec30279814d9ad017d80714ffa22c5212081543'
source = json.loads(a.source.read_text())
assert source['all_four_root_descriptions_equal']
root = next(x for x in source['roots'] if x['root_index'] == 0)
assert root['domain'] == 0 and root['perst_GPIO'] == 94 and root['wake_GPIO'] == 96
def pairs(values):
    assert len(values) % 4 == 0
    return [(int(values[i],16),int(values[i+2],16),int(values[i+3],16)) for i in range(0,len(values),4)]
ids = pairs(root['iommu_map'])
assert ids == pairs(root['msi_map']) == [(0,0x1400,1),(0x100,0x1401,1)]
sel = json.loads(a.selector.read_text())['capture']['result']
assert sel['capture_code'] == 0 and sel['source_root0_selection_qualified'] and sel['source_selected_root_complex'] == 0 and sel['source_selected_device_id'] == '0x1107'
u32 = lambda data, at: struct.unpack_from('<I', data, at)[0]
u16 = lambda data, at: struct.unpack_from('<H', data, at)[0]
assert b[:4] == b'IORT' and u32(b,4)==len(b) and sum(b)%256==0
at = u32(b,40)
nodes = []
for _ in range(u32(b,36)):
    length = u16(b,at+1)
    assert length>=16 and at+length<=len(b)
    nodes.append((at,length,b[at]))
    at += length
assert at == len(b)
roots = [n for n,l,t in nodes if t==2 and u32(b,n+28)==0]
assert roots == [0x490]
n = roots[0]
count, offset = u32(b,n+8), u32(b,n+12)
assert count == 6 and offset == 36 and u16(b,n+1)==156
ref = u32(b,n+offset+12)
assert ref == 0x30 and b[ref] == 3
out = bytearray(b)
struct.pack_into('<I',out,n+8,len(ids))
out[n+offset:n+offset+20*count] = bytes(20*count)
for i,(rid,sid,length) in enumerate(ids):
    struct.pack_into('<5I',out,n+offset+20*i,rid,length-1,sid,ref,0)
out[9] = 0
out[9] = (-sum(out))&255
changed = [i for i,(old,new) in enumerate(zip(b,out)) if old!=new]
allowed = {9,*range(n+8,n+12),*range(n+offset,n+offset+20*count)}
assert set(changed)<=allowed and sum(out)%256==0 and len(out)==len(b)
for pos,length,kind in nodes:
    if pos != n:
        assert bytes(out[pos:pos+length])==b[pos:pos+length]
    else:
        assert bytes(out[pos:pos+8])==b[pos:pos+8] and u16(out,pos+1)==length
a.output.write_bytes(out)
r = {'status':'Offline candidate only; not installed or hardware qualified',
     'source_IORT_sha256':hashlib.sha256(b).hexdigest(),
     'candidate_sha256':hashlib.sha256(out).hexdigest(),
     'candidate_bytes':len(out),'changed_bytes':len(changed),'changed_offsets':changed,
     'root0_node_offset':hex(n),'old_mapping_count':count,'new_mapping_count':len(ids),
     'pairs':[{'input_selector':hex(rid),'output_stream':hex(sid),'count':length}for rid,sid,length in ids],
     'all_other_nodes_identical':True,'all_node_offsets_and_lengths_preserved':True,
     'DSDT_changes':0,'root0_unused_slots':'Zero padding within existing node length',
     'limits':['Source SID pairs are not an observed endpoint identity or live PARF BDF/SID configuration.',
               'Loaded-kernel catalogue, PCIe initialization, ACPI root exposure, DMA/MSI and device operation remain unqualified.',
               'Expose a new PCI root through an additional SSDT after hardware initialization; preserve the exact DSDT used by touch guards.'],
     'native_operations':0}
a.report.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:v for k,v in r.items()if k!='changed_offsets'},indent=2))
