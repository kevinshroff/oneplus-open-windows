"""Inspect this retained capture offline; never submit a native operation."""
from pathlib import Path
import ast,hashlib,json,re,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';raw=(p/'native-capture.bin').read_bytes()
load=lambda n:json.loads((p/n).read_text());sha=lambda b:hashlib.sha256(b).hexdigest()
receipt=load('native-capture-result.json');client=json.loads(receipt['output']);intent=load('native-capture-intent.json')
assert receipt['status']=='ok'and client['ok']and len(raw)==5243168 and sha(raw)==client['sha256']
assert raw[8:16]==b'OG135MR1'and struct.unpack_from('<Q',raw,80)[0]==int(intent['nonce'],16)
q=subprocess.run(['go','run','main_offline.go','g135_decode.go',str((p/'native-capture.bin').resolve()),intent['nonce']],cwd=w/'probe',capture_output=True,text=True)
assert q.returncode==0,q.stderr;decoded=json.loads(q.stdout);(p/'decoded-native-r2.json').write_text(json.dumps(decoded,indent=2)+'\n')
assert decoded['operation_code']==0 and decoded['complete_mask']==31 and decoded['maps']==10 and decoded['region_count']==5
regions=[]
for row in decoded['regions']:
 off=row['offset'];n=row['bytes'];first=raw[288+off:288+off+n];second=raw[288+off+n:288+off+2*n]
 assert len(first)==len(second)==n and first==second and sha(first)==row['first_sha256']==row['second_sha256']
 regions.append((row,first,second))
toc=regions[1][1];assert toc[:4]==b'$TOC'and struct.unpack_from('<I',toc,4)[0]==1
count=struct.unpack_from('<I',toc,8)[0];assert 0<count<=64
table=[]
for i in range(count):
 off,n,flags,h0,h1,cl=struct.unpack_from('<IIIHHI',toc,32+48*i)
 table.append({'offset':off,'bytes':n,'flags':flags,'host0':h0,'host1':h1,'cacheline':cl})

# Reuse the previously validated offline item-format functions without executing
# that script's command-line, file, DTB or native-capture setup.
source=(w.parent/'charging-G108/inspect-capture.py').read_text()
nodes=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name in ['partition','smp2p']]
assert len(nodes)==2
ns={'struct':struct,'sha':sha};exec(compile(ast.Module(body=nodes,type_ignores=[]),'G108-item-format-functions','exec'),ns)
parts=[]
for row,first,second in regions[3:]:
 entries=[e for e in table if e['offset']==int(row['address'],16)-0x81d00000 and e['bytes']==row['bytes']and(e['host0'],e['host1'])==(row['host0'],row['host1'])];assert len(entries)==1
 parsed=ns['partition'](first,entries[0]);items=parsed['items'];byid={x['id']:x for x in items};candidates={}
 for ident in [429,443]:
  if ident in byid:
   try:candidates[str(ident)]=ns['smp2p'](byid[ident]['data'])
   except(AssertionError,struct.error):candidates[str(ident)]={'format_valid':False}
 descriptor=None
 if 478 in byid and len(byid[478]['data'])==32:
  words=list(struct.unpack('<8I',byid[478]['data']));descriptor={'words':words,'transport_ownership_qualified':False}
 for item in items:item.pop('data')
 parts.append({'address':row['address'],'host0':row['host0'],'host1':row['host1'],'both_samples_match':True,'complete_inventory':True,'items':items,'SMP2P_candidates':candidates,'GLINK_descriptor_candidate':descriptor,'TX_FIFO_479_present':479 in byid,'RX_FIFO_480_present':480 in byid})
assert len(parts)==2
log=regions[2][1];(p/'retained-firmware-log.bin').write_bytes(log)
strings=[m.group().decode('ascii')for m in re.finditer(rb'[\x20-\x7e]{8,}',log)]
strings += [m.group().decode('utf-16le')for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}',log)]
tz=[s for s in strings if re.search(r'tz_armv8_smc_call failed.*TzStatus\s*=\s*0x[0-9a-f]+.*SmcId\s*=\s*0x[0-9a-f]+',s,re.I)]
relevant=[s[:400]for s in strings if re.search(r'TzStatus|SmcId|\badsp\b|\bPIL\b|\bSMC\b',s,re.I)and not re.search(r'password|token|secret|key\s*[=:]',s,re.I)][:60]
adsp=next(x for x in parts if {x['host0'],x['host1']}=={0,2});global_=next(x for x in parts if x['host0']==x['host1']==0xfffe)
r={'capture_sha256':sha(raw),'session':intent['session'],'G134_report_sha256':json.loads(load('native-load-result.json')['output'])['G134_report_sha256'],'native_duration_ms':(decoded['end_100ns']-decoded['begin_100ns'])/10000,'physical_bytes_read':decoded['read_bytes'],'all_five_regions_match_between_samples':True,'physical_writes':0,'PAS_requests_by_G135':0,'SMEM_partition_table':table,'SMEM_selected_partitions':parts,'retained_log_sha256':sha(log),'retained_log_bytes':len(log),'retained_log_TzStatus_lines':tz,'retained_log_relevant_lines':relevant,'global_item_count':len(global_['items']),'ADSP_item_ids':[x['id']for x in adsp['items']],'ADSP_RX_FIFO_480_present':adsp['RX_FIFO_480_present'],'DSP_running_qualified':False,'GLINK_ready_qualified':False,'charging_qualified':False,'decoder_correction':'Initial client compared 64 extra bytes per sample; exact-size R2 decoder reuses the same verified raw file. Initial receipt retained; no second capture.','limits':['A retained log entry may predate this request unless its provenance is independently tied to this boot.','Absent standard structures or silent short samples do not prove DSP is powered off.','Structured shared-memory presence alone does not prove a live charger reply.','No global DMA ownership, production PnP ownership or charging claim is made.']}
(p/'passive-analysis.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:r[k]for k in ['native_duration_ms','physical_bytes_read','all_five_regions_match_between_samples','global_item_count','ADSP_item_ids','ADSP_RX_FIFO_480_present','retained_log_TzStatus_lines','retained_log_relevant_lines']},indent=2))
