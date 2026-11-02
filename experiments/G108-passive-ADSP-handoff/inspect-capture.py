"""Offline decoder for a frozen G108 passive RAM capture; no native access."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser(description=__doc__)
for n in ['capture','receipt','intent','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
raw=a.capture.read_bytes();receipt=json.loads(a.receipt.read_text());client=json.loads(receipt['output']);intent=json.loads(a.intent.read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
assert len(raw)==5243232 and sha(raw)==client['sha256'] and receipt['status']=='ok'
u=lambda o:struct.unpack_from('<I',raw,o)[0]
q=lambda o:struct.unpack_from('<Q',raw,o)[0]
assert raw[8:16]==b'OG108MR1' and q(80)==int(intent['nonce'],16)
assert u(120)<=7 and u(124)<=0x500000
initial_only=u(88)==2003 and u(120)==5 and u(92)==0 and u(96)==311496 and u(100)==5
a.output.mkdir()
report={'capture_sha256':sha(raw),'controller_UTC':receipt['created_utc'],'session':receipt['session'],
        'operation_code':u(88),'complete_mask':u(92),'physical_bytes_read':u(96),'map_calls':u(100),
        'begin_100ns':q(104),'end_100ns':q(112),'native_operations_by_decoder':0,'regions':[],
        'limits':['A prior handshake or firmware load record alone does not prove a DSP is currently running.',
                  'Silent shared memory over this short interval does not establish that a subsystem is off.',
                  'No DSP, charger, register, FIFO index or SMEM allocation is written by this observer.',
                  'A RAM-resident DTB is captured boot data; Android kernel tree selection is not inferred.']}
regions=[];next_offset=0
for i in range(u(120)):
 address,size,offset,h0,h1,kind,status=struct.unpack_from('<Q6I',raw,128+32*i)
 assert offset==next_offset and 0<size<=0x100000 and 2*size<=u(124)-offset
 first=raw[352+offset:352+offset+size];second=raw[352+offset+size:352+offset+2*size]
 row={'address':hex(address),'bytes':size,'kind':kind,'host0':h0,'host1':h1,'status':status,
      'first_sha256':sha(first),'second_sample_captured':bool(u(92)&(1<<i))}
 if row['second_sample_captured']:row.update(second_sha256=sha(second),different_bytes=sum(x!=y for x,y in zip(first,second)))
 regions.append((row,first,second));report['regions'].append(row);next_offset+=2*size
assert next_offset==u(124)
if u(88)!=0 and not initial_only:
 report['scope']='Capture refused or incomplete; no subsystem-state conclusion.'
 (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));raise SystemExit
if not initial_only:assert u(92)==127 and u(96)==next_offset and u(100)==14 and len(regions)==7
else:report['scope']='Five initial regions completed once. No processor-pair partition read; second samples are uncaptured zeros, not changes.'
toc=regions[1][1];assert toc[:4]==b'$TOC'
if not initial_only:assert toc==regions[1][2]
count=struct.unpack_from('<I',toc,8)[0];assert 0<count<=64
table=[]
for i in range(count):
 off,size,flags,h0,h1,cacheline=struct.unpack_from('<IIIHHI',toc,32+48*i)
 table.append({'offset':off,'bytes':size,'flags':flags,'host0':h0,'host1':h1,'cacheline':cacheline})
report['SMEM_partition_table']=table
header=regions[0][1]
report['SMEM_header']={'bootloader_version_word':hex(struct.unpack_from('<I',header,64+7*4)[0]),
                       'initialized':struct.unpack_from('<I',header,192)[0]}

def partition(data,entry):
 assert len(data)==entry['bytes'] and data[:4]==b'$PRT'
 h0,h1,size,free_u,free_c=struct.unpack_from('<HHIII',data,4)
 assert (h0,h1)==(entry['host0'],entry['host1']) and size==len(data) and 32<=free_u<=free_c<=size
 result=[];ids=set();cacheline=entry['cacheline'];assert cacheline and cacheline&(cacheline-1)==0
 def item(at,cached):
  assert 0<=at<=size-16
  canary,ident,n,padding,hpad,reserved=struct.unpack_from('<HHIHHI',data,at)
  assert canary==0xa5a5 and ident not in ids and 0<n<size and padding<n
  start=at-n if cached else at+16+hpad
  assert start>=32 and start+n<=size
  value=data[start:start+n-padding];ids.add(ident)
  result.append({'id':ident,'cached':cached,'relative_offset':start,'bytes':len(value),'sha256':sha(value),'data':value})
  return at-n-((16+cacheline-1)&-cacheline) if cached else start+n
 at=32
 while at<free_u:
  assert len(result)<4096
  after=item(at,False);assert at<after<=free_u;at=after
 assert at==free_u
 at=size-((16+cacheline-1)&-cacheline)
 while at>free_c:
  assert len(result)<4096
  after=item(at,True);assert free_c-((16+cacheline-1)&-cacheline)<=after<at;at=after
 return {'host0':h0,'host1':h1,'free_uncached':free_u,'free_cached':free_c,'items':result}

def smp2p(value):
 assert len(value)>=20
 magic,version,pids,total,valid,flags=struct.unpack_from('<II I HH I',value)
 assert magic==0x504d5324 and version&255==1 and total<=16 and valid<=total and len(value)>=20+20*valid
 entries=[]
 for i in range(valid):
  name,state=struct.unpack_from('<16sI',value,20+20*i)
  entries.append({'name':name.split(b'\0',1)[0].decode('ascii','backslashreplace'),'value':hex(state)})
 return {'local_pid':pids&65535,'remote_pid':pids>>16,'features':version>>8,'flags':flags,'entries':entries}

parts=[]
for region,first,second in regions[5:]:
 entry=next(e for e in table if e['offset']==int(region['address'],16)-0x81d00000 and e['bytes']==region['bytes'] and e['host0']==region['host0'] and e['host1']==region['host1'])
 samples=[]
 for sample,data in enumerate((first,second)):
  try:
   parsed=partition(data,entry);byid={x['id']:x for x in parsed['items']}
   parsed['SMP2P_candidates']={}
   for ident in (429,443):
    if ident in byid:
     try:parsed['SMP2P_candidates'][str(ident)]=smp2p(byid[ident]['data'])
     except (AssertionError,struct.error) as error:parsed['SMP2P_candidates'][str(ident)]={'format_valid':False,'error':type(error).__name__}
   if 478 in byid and len(byid[478]['data'])==32:
    parsed['Linux_GLINK_descriptor_candidate']={'words':list(struct.unpack('<8I',byid[478]['data'])),'format_ownership_proven':False}
   for row in parsed['items']:row.pop('data')
   parsed['sample']=sample;parsed['complete_inventory']=True;samples.append(parsed)
  except (AssertionError,struct.error,StopIteration) as error:samples.append({'sample':sample,'complete_inventory':False,'error':type(error).__name__})
 parts.append({'address':region['address'],'samples':samples})
report['SMEM_selected_partitions']=parts

imem=regions[4][1];pil=[];invalid_pil=[]
for at in range(0,200,20):
 name,base,size=struct.unpack_from('<8sQI',imem,at)
 if name.strip(b'\0') or base or size:
  row={'slot':at//20,'raw_name_hex':name.hex(),'base':hex(base),'bytes':size}
  if re.fullmatch(rb'[A-Za-z0-9_]{1,8}\x00*',name) and base>=0x80000000 and base%4096==0 and size and size%4096==0 and base+size<1<<64:
   row['name']=name.rstrip(b'\0').decode();pil.append(row)
  else:invalid_pil.append(row)
report['PIL_relocation_records']=pil
report['PIL_nonempty_slots_without_valid_record_format']=invalid_pil
trees=[];blob=regions[2][1]
for at in range(0,len(blob)-40,4):
 if blob[at:at+4]!=b'\xd0\x0d\xfe\xed':continue
 fields=struct.unpack_from('>10I',blob,at);size=fields[1]
 if size<40 or size>len(blob)-at or fields[5] not in (16,17):continue
 data=blob[at:at+size];path=a.output/('boot-data-'+hex(at)+'.dtb');path.write_bytes(data)
 out=path.with_suffix('.dts');r=subprocess.run(['dtc','-I','dtb','-O','dts','-o',str(out),str(path)],capture_output=True,text=True)
 row={'offset':at,'bytes':size,'sha256':sha(data),'DTC_pass':r.returncode==0}
 (out.with_suffix('.dtc.log')).write_text(r.stderr)
 if r.returncode==0:
  lines=out.read_text().splitlines();row['root_properties']=[s for s in lines if re.match(r'^\t(?:model|compatible|qcom,msm-id|qcom,board-id|oplus,project-id) = ',s)]
  row['relevant_lines']=[s for s in lines if any(word in s.lower() for word in ('adsp','demura','xport-smem','pmic_rtr','charger')) and len(s)<400]
 trees.append(row)
report['RAM_resident_FDT_candidates']=trees
log=regions[3][1]
strings=[m.group().decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{8,}',log)]
report['UEFI_log_diagnostic_strings']=[s for s in strings if re.search(r'adsp|glink|charger|pil |demura|dtb|fail|error',s,re.I) and not re.search(r'key|password|token|secret',s,re.I)][:100]
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'operation_code':report['operation_code'],'regions':len(regions),'PIL_records':len(pil),
                  'FDT_candidates':len(trees),'partition_inventory_valid':[[s['complete_inventory'] for s in p['samples']] for p in parts]}))
