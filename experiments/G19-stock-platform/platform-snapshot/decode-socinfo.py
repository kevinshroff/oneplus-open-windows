"""Walk the captured SMEM-v12 allocation headers; expose only SoC revision facts."""
from pathlib import Path
import hashlib,json,struct
from importlib.util import module_from_spec,spec_from_file_location
W=Path(__file__).resolve().parent
sp=spec_from_file_location('physical',W/'decode-physical.py');m=module_from_spec(sp);sp.loader.exec_module(m)
p2,(a2,b2)=m.latest('G19_P2');p3,(a3,b3)=m.latest('G19_P3');p4,(a4,b4)=m.latest('G19_P4');p5,(a5,b5)=m.latest('G19_P5');a={**a2,**a3,**a4,**a5};b={**b2,**b3,**b4,**b5}
base=0x81d01000;size=0xb0000;header=m.read(a,base,32);assert header==m.read(b,base,32) and header[:4]==b'$PRT'
h0,h1,n,freeu,freec=struct.unpack_from('<HHIII',header,4);assert h0==h1==0xfffe and n==size and 32<=freeu<=freec<=size
seen=[];cursor=32;soc=None
while cursor<freeu:
 try:raw=m.read(a,base+cursor,16)
 except KeyError:
  print('CAPTURE_GAP next_header_address',hex(base+cursor),'walked_items',json.dumps(seen));break
 assert raw==m.read(b,base+cursor,16)
 canary,item,n,pad,padh,res=struct.unpack('<HHIHHI',raw)
 assert canary==0xa5a5 and item<654 and pad<=n and padh<=4096 and res==0 and n<=freeu-cursor-16-padh
 dataaddr=base+cursor+16+padh;seen.append({'item':item,'data_address':hex(dataaddr),'bytes':n-pad,'entry_offset':hex(cursor)})
 if item==137:
  assert n-pad>=12
  raw=m.read(a,dataaddr,12);assert raw==m.read(b,dataaddr,12);fmt,ident,revision=struct.unpack('<III',raw)
  assert 0<fmt<0x10000 and 0<ident<4096
  soc={'format':fmt,'soc_id':ident,'revision_raw':revision,'revision_major':revision>>16,'revision_minor':revision&0xffff,'SMEM_item':137,'physical_address':hex(dataaddr),'core_fields_sha256':hashlib.sha256(raw).hexdigest(),'core_fields_double_read_equal':True}
  platform={}
  for name,off in [('hw_platform',52),('platform_version',56),('hw_platform_subtype',64),('chip_family',108),('feature_code',176),('product_code',180),('oem_variant',192)]:
   assert n-pad>=off+4
   v=m.read(a,dataaddr+off,4);assert v==m.read(b,dataaddr+off,4);platform[name]=struct.unpack('<I',v)[0]
  soc['selected_nonserial_platform_fields']=platform
  soc['layout_reference']='Linux v6.12 include/linux/soc/qcom/socinfo.h; format18 common prefix confirmed'
  print('LIVE_SOCINFO',json.dumps(soc,indent=2));break
 cursor+=16+padh+n
assert len(seen)<=654
r={'source':'read-only uncached native SMEM-v12 snapshot in existing G17 boot','global_partition_base':hex(base),'global_partition_size':size,'uncached_allocated_end':hex(base+freeu),'validated_allocation_headers_to_socinfo':seen,'socinfo':soc,'capture_gap_next_header':None if soc else hex(base+cursor),'source_logs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [p2,p3,p4,p5]},'scope':'SoC identity/revision observation; does not prove bootloader DTBO/panel selection','GICD_UFS_recheck':{hex(address):a3[address] for address in [0x17100124,0x17100224,0x17100324,0x1d84020,0x1d84024,0x1d84058,0x1d84064]},'target_raw_writes':0}
(W/'socinfo-live-result.json').write_text(json.dumps(r,indent=2)+'\n')
