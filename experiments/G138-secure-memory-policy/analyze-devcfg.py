"""Decode the shipped DAL property chain observed in the TZ implementation.

Only local immutable partition captures are read. This is a reconstruction,
not a read of live secure globals; REA byte witnesses bind the selected fields.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

w=Path(__file__).resolve().parent
def analyze(path):
    raw=path.read_bytes()
    assert len(raw)==131072 and raw[:6]==b'\x7fELF\x02\x01'
    hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    assert hdr[2]==183 and hdr[4]==0xd8300000 and hdr[9]==56 and hdr[10]==4
    loads=[]
    for i in range(hdr[10]):
        typ,flags,off,va,pa,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',raw,hdr[5]+i*56)
        assert off+filesz<=len(raw)
        if typ==1:loads.append((va,off,filesz))
    def read(address,n):
        rows=[(va,off,size) for va,off,size in loads if va<=address<=address+n<=va+size]
        assert len(rows)==1, 'Unique file-backed ELF mapping required.'
        va,off,size=rows[0];return raw[off+address-va:off+address-va+n]
    def cstr(address):
        data=bytearray()
        for i in range(160):
            ch=read(address+i,1)[0]
            if ch==0:return data.decode('ascii')
            data.append(ch)
        raise AssertionError('Unterminated bounded property name')
    flavors=[]
    for i in range(4):
        at=0xd8300000+32*i
        device,info=struct.unpack('<I4xQ',read(at,16))
        if not info:break
        flavors.append((device,info))
    assert len(flavors)==1 and flavors[0][0]==0xa003
    info_address=flavors[0][1]
    directory,structs,count,devices=struct.unpack('<QQQQ',read(info_address,32))
    assert 0<count<=256
    matches=[]
    for i in range(count):
        address=devices+i*40
        name,hashed,prop_offset,unused,collisions,pad,collision_pointer=struct.unpack('<QIIQIIQ',read(address,40))
        if cstr(name)=='/tz/oem':
            assert hashed==0x3d0286b2 and collisions==0
            matches.append({'address':address,'name_address':name,'offset':prop_offset})
    assert len(matches)==1
    head=struct.unpack('<8I',read(directory,32))
    pos=directory+matches[0]['offset'];selected={}
    wanted={'OEM_pil_subsys_load_region_start','OEM_pil_subsys_load_region_size'}
    for i in range(128):
        encoded,value=struct.unpack('<II',read(pos,8))
        if encoded==0xff00ff00:break
        typ=encoded>>24
        name_address=directory+head[1]+(encoded&0x7fffff)
        name=cstr(name_address)
        if name in wanted:
            assert typ==2 and name not in selected
            selected[name]={'record_address':pos,'name_address':name_address,
                            'record_hex':read(pos,8).hex(),'value':value,'type':typ}
        if typ==8:
            n=read(pos+4,1)[0];assert n<250
            pos+=4+((n+2+3)&~3)
        else:
            assert typ in (2,0x11,0x12,0x14,0x18)
            pos+=8
    else:raise AssertionError('Property terminator missing')
    assert set(selected)==wanted
    start=selected['OEM_pil_subsys_load_region_start']['value']
    size=selected['OEM_pil_subsys_load_region_size']['value']
    assert start%4096==0 and size>0 and size%4096==0 and start+size<1<<32
    return {'partition':path.stem,'sha256':hashlib.sha256(raw).hexdigest(),
            'flavor':flavors[0][0],'propsinfo_address':info_address,'directory':directory,
            'oem_device':matches[0],'selected':selected,'start':start,'size':size,'end_exclusive':start+size,
            'G134_DTB_range_inside':start<=0xa9f80000 and 0xa9f80000+0x80000<=start+size,
            'original_DTB_range_inside':start<=0x9e980000 and 0x9e980000+0x80000<=start+size,
            'original_main_range_inside':start<=0x9ea00000 and 0x9ea00000+0x4880000<=start+size}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir',type=Path,default=w/'private')
    parser.add_argument('--output',type=Path,default=w/'private/devcfg-policy.json')
    args=parser.parse_args()
    assert not args.output.exists(), 'Keep prior evidence; choose a new output path.'
    results=[analyze(args.input_dir/(n+'.img')) for n in ['devcfg_a','devcfg_b']]
    args.output.write_text(json.dumps(results,indent=2)+'\n')
    for r in results:
        print(json.dumps({'partition':r['partition'],'start':hex(r['start']),
                          'end_exclusive':hex(r['end_exclusive']),
                          'property_records':{k:hex(v['record_address']) for k,v in r['selected'].items()},
                          'G134_DTB_range_inside':r['G134_DTB_range_inside']}))
