"""Offline byte comparison of a captured published/retained graph, never an inactive audit.
No target access, source callbacks, simulated completion or hardware translation claim.
"""
from pathlib import Path
import argparse,json,hashlib,struct
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',type=Path,required=True);p.add_argument('--captured-dir',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 m=json.loads(a.plan.read_text());assert m['schema']=='G1325-retained-published-CPU-copy/1' and type(m.get('BootId')) is int and m['BootId']>0
 assert not a.out.exists();issues=[];data={};hashes={}
 def need(value,message):
  if not value:issues.append(message)
 def finish(rows=None,compared=0):
  report={'schema':'G1325-captured-published-CPU-graph-audit/1','result':'pass'if not issues else'fail','BootId':m['BootId'],'phone_session':m['phone_session'],'plan_sha256':sha(a.plan),'captured_files':hashes,'issues':issues,'descriptor_entries_compared':compared,'pool_pages':3,'MDL_page_counts':[8,1,19,1],'MDL_pages_compared':len(rows or []),'pages':rows or [],'scope':'Captured CPU bytes and MDL PFNs only; all unused descriptors also compared. No currentness callback/inactive-audit API invoked. No GPU fetch, hardware walk, ATS, cache coherency or completion is established.'}
  with a.out.open('x')as f:json.dump(report,f,indent=2);f.write('\n')
  print(a.out);raise SystemExit(2 if issues else 0)
 for key,meta in m['files'].items():
  path=a.captured_dir/meta['name'];need(path.is_file(),'Missing '+key)
  if path.is_file():
   raw=path.read_bytes();need(len(raw)==meta['bytes'],'Wrong size '+key);data[key]=raw;hashes[key]={'name':meta['name'],'bytes':len(raw),'sha256':sha(path)}
 if issues:finish()
 for kind in ('retained-global','owner','cp','pool','ranges','mdl0','mdl1','mdl2','mdl3'):need(data[kind+'-before']==data[kind+'-after'],'Before/after bytes differ: '+kind)
 q=lambda x,o:struct.unpack_from('<Q',x,o)[0]
 d=lambda x,o:struct.unpack_from('<I',x,o)[0]
 w=lambda x,o:struct.unpack_from('<H',x,o)[0]
 canonical=lambda address,length:address>>48==0xffff and address%8==0 and address<=(1<<64)-length
 owner=data['owner-before'];cp=data['cp-before'];root=int(m['expected_root_physical'],16);ranges=data['ranges-before'];pool=data['pool-before']
 op=q(data['retained-global-before'],0);cp_pointer=q(owner,0x558)
 need(canonical(op,0x568),'Bad retained owner pointer');need(canonical(cp_pointer,0x5700),'Bad CP pointer')
 for off,size,value,name in [(0x100,8,1,'generation'),(0x110,8,int(m['expected_run_id'],16),'run id'),(0x510,4,8,'owner phase'),(0x518,4,0xc0000483,'owner status'),(0xd8,4,1,'revoked'),(0xdc,4,2,'once'),(0xe0,2,0,'started/D0'),(0xe2,1,1,'removing'),(0xe5,2,0,'thread/power busy'),(0xe7,1,1,'uncertain'),(0xf0,8,0,'operation thread')]:
  got=int.from_bytes(owner[off:off+size],'little');need(got==value,'Unexpected '+name)
 checks=[(0x5438,4,4),(0x5470,4,0xc0000483),(0x5474,1,0),(0x5475,1,1),(0x5476,1,0),(0x5477,1,1),(0x5478,1,1),(0x56f8,1,1),(0x228,4,3),(0x5360,4,2),(0x5370,8,root),(0x5378,8,0x3000),(0x5380,4,0),(0x5384,4,0x4e435047),(0x5390,8,29),(0x53a0,4,39),(0x53a4,4,36),(0x53a8,8,root),(0x53b8,8,root),(0x53c0,8,0xff44),(0x53c8,8,3),(0x53d0,8,29),(0x53d8,4,1),(0x53dc,4,0),(0x5424,1,1)]
 for off,size,value in checks:need(int.from_bytes(cp[off:off+size],'little')==value,f'Unexpected CP field {off:#x}')
 need(canonical(q(cp,0x5368),0x3000)and q(cp,0x5368)%4096==0,'Bad pool CPU address');need(canonical(q(cp,0x5388),29*40),'Bad ranges address')
 iovas=[0x4000000000,0x4000008000,0x4000010000,0x4000030000];counts=[8,1,19,1];rows=[]
 for i,(iova,count)in enumerate(zip(iovas,counts)):
  mdl=data[f'mdl{i}-before'];mdl_pointer=q(cp,0xd0+i*0x18);cpu_pointer=q(cp,0xd8+i*0x18)
  need(canonical(mdl_pointer,0x30+count*8),f'Bad mdl{i} pointer');need(canonical(cpu_pointer,count*4096),f'Bad BO{i} CPU pointer')
  need(q(cp,0x130+i*8)==iova and q(cp,0x150+i*8)==count*4096,f'Wrong fixed BO{i} layout')
  need(cp[0xe0+i*0x18]==cp[0xe1+i*0x18]==1,f'BO{i} not published/mapped')
  need(w(mdl,8)>=0x30+count*8 and w(mdl,10)&2 and d(mdl,0x28)==count*4096 and d(mdl,0x2c)==0,f'Bad locked MDL{i} bounds')
  for page in range(count):
   pfn=q(mdl,0x30+8*page);va=iova+page*4096;pa=pfn*4096
   need(pfn<1<<24,f'PFN exceeds36-bit output BO{i}/{page}');need(not(root<=pa<root+0x3000),f'BO{i}/{page} overlaps table pool')
   rows.append({'BO':i,'page':page,'iova':hex(va),'PFN':hex(pfn),'physical':hex(pa),'expected_descriptor':hex(pa|0xe03)})
 expected=[0]*1536;expected[256]=(root+0x1000)|3;expected[512]=(root+0x2000)|3
 for i,row in enumerate(rows):
  va=int(row['iova'],16);pa=int(row['physical'],16);record=struct.unpack_from('<QQQIII',ranges,i*40)
  need(record==(va,pa,4096,15,0,2),f'Range{i} differs from retained MDL/source permissions/cache')
  slot=1024+((va>>12)&511);expected[slot]=pa|0xe03;row['pool_descriptor_offset']=hex(slot*8);row['captured_descriptor']=hex(q(pool,slot*8))
 actual=list(struct.unpack('<1536Q',pool));mismatches=[]
 for i,(got,wanted)in enumerate(zip(actual,expected)):
  if got!=wanted:mismatches.append({'pool_offset':hex(i*8),'captured':hex(got),'expected':hex(wanted)})
 need(not mismatches,'CPU table graph differs: '+json.dumps(mismatches[:64],separators=(',',':')))
 finish(rows,1536)
if __name__=='__main__':main()
