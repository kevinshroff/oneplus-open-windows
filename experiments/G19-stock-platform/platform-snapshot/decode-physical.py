"""Parse bounded WinDbg !dd output without exposing unrelated log or private data."""
from pathlib import Path
import hashlib,json,re,struct
W=Path(__file__).resolve().parent

def section(text,tag):
    text=text.replace('\r\n','\n');start=text.rfind('\n'+tag+'_BEGIN\n');end=text.rfind('\n'+tag+'_END\n')
    if start<0 or end<start:raise ValueError('capture markers missing')
    block=text[start+len('\n'+tag+'_BEGIN\n'):end]
    return block.split('\n'+tag+'_REPEAT\n')
def words(block):
    result={}
    for line in block.splitlines():
        m=re.fullmatch(r'#\s*([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F]{8}(?:\s+|$))+)',line)
        if not m:continue
        addr=int(m[1].replace('`',''),16)
        for i,value in enumerate(m[2].split()):
            address=addr+4*i;v=int(value,16)
            if address in result and result[address]!=v:raise ValueError('conflicting reads')
            result[address]=v
    return result
def read(mapping,addr,n):
    out=bytearray()
    while len(out)<n:
        base=addr+len(out);aligned=base&~3
        if aligned not in mapping:raise KeyError(hex(aligned))
        b=struct.pack('<I',mapping[aligned]);offset=base-aligned;out+=b[offset:offset+min(4-offset,n-len(out))]
    return bytes(out)
def latest(tag):
    for p in sorted((W/'private').glob('debug-live-*.txt'),reverse=True):
        text=p.read_bytes().decode('utf8','replace')
        try:blocks=section(text,tag)
        except ValueError:continue
        if len(blocks)==2:return p,[words(b) for b in blocks]
    raise FileNotFoundError(tag)
if __name__=='__main__':
    p0,(a0,b0)=latest('G19_P0');p1,(a1,b1)=latest('G19_P1');p2,(a2,b2)=latest('G19_P2')
    header=read(a0,0x81d00000,256);assert header==read(b0,0x81d00000,256)
    toc=read(a1,0x81eff000,0x300);assert toc==read(b1,0x81eff000,0x300)
    assert toc[:4]==b'$TOC';version,count=struct.unpack_from('<II',toc,4);assert version==1 and count==15
    assert toc[32+count*48:32+count*48+4]==b'SIII'
    item_info=read(a2,0x81eff300,16);assert item_info==read(b2,0x81eff300,16)
    entries=[]
    for i in range(count):
        off,n,flags,h0,h1,cache=struct.unpack_from('<IIIHHI',toc,32+i*48)
        assert off<=0x200000 and n<=0x200000-off
        entries.append({'index':i,'offset':off,'bytes':n,'flags':flags,'host0':h0,'host1':h1,'cacheline':cache})
    glob=[x for x in entries if x['host0']==x['host1']==0xfffe];assert len(glob)==1;g=glob[0]
    addr=0x81d00000+g['offset'];block=read(a2,addr,4096);assert block==read(b2,addr,4096)
    print('global descriptor',json.dumps(g),'address',hex(addr),'first32hex',block[:32].hex(),'nonzero byte count first4096',sum(v!=0 for v in block),'item count',struct.unpack_from('<H',item_info)[0])
    if block[:4]==b'$PRT':
        h0,h1,n,freeu,freec=struct.unpack_from('<HHIII',block,4);assert h0==h1==0xfffe and n==g['bytes'];print('GLOBAL_HEADER',h0,h1,n,hex(freeu),hex(freec))
        cursor=32;seen=[]
        while cursor<min(freeu,len(block)):
            canary,item,n,pad,padh,res=struct.unpack_from('<HHIHHI',block,cursor);assert canary==0xa5a5 and pad<=n and padh<=4096 and n<=g['bytes']-cursor-16-padh
            dataaddr=addr+cursor+16+padh;seen.append({'item':item,'address':hex(dataaddr),'bytes':n-pad,'entry_offset':hex(cursor)})
            if item==137:
                core=read(a2,dataaddr,12);assert core==read(b2,dataaddr,12);fmt,soc,revision=struct.unpack('<III',core);print('SOCINFO_CORE',fmt,soc,hex(revision))
            cursor+=16+padh+n
        print('seen item headers',json.dumps(seen));print('next header offset',hex(cursor))
    r={'scope':'read-only explicitly uncached snapshot; no disk/MMIO writes','source_logs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [p0,p1,p2]},'SMEM_version_word':struct.unpack_from('<I',header,0x5c)[0],'SMEM_header_double_read_equal':True,'SMEM_TOC_double_read_equal':True,'SMEM_global_prefix_double_read_equal':True,'SMEM_num_items':struct.unpack_from('<H',item_info)[0],'SMEM_partition_entries':entries,'SMEM_global_descriptor':g,'SMEM_global_header_magic_hex':block[:4].hex(),'SMEM_global_prefix_nonzero_bytes':sum(v!=0 for v in block),'GICD':{hex(a):a0[a] for a in [0x17100000,0x17100004,0x17100008,0x1710000c,0x171000a4,0x17100124,0x17100224,0x17100324,0x17100c48,0x17106948,0x1710694c]},'UFS_HCI':{hex(a):a0[a] for a in [0x1d84020,0x1d84024,0x1d84030,0x1d84034,0x1d84058,0x1d84064]}}
    (W/'platform-live-initial.json').write_text(json.dumps(r,indent=2)+'\n')
