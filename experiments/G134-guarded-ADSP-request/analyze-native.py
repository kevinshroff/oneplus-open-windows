"""Cross-bind the three G134 captures, retaining diagnostic failures as facts."""
from pathlib import Path
import hashlib,json,base64,struct,re
w=Path(__file__).resolve().parent;p=w/'private'
load=lambda n:json.loads((p/n).read_text())
d=load('DSP-native.json');m=load('OPAS-native.json');a=load('raw-OAPF-native.json')
assert d['ok'],'Decode retained native-OADP.bin before interpreting a refused reader result'
r=d['report'];meta=m.get('report',{});b=(p/'native-OADP.bin').read_bytes()
assert hashlib.sha256(b).hexdigest()==r['table_sha256']
assert a.get('ok')and a['stable_double_read']
raw=(p/'native-OAPF.bin').read_bytes();assert hashlib.sha256(raw).hexdigest()==a['sha256']
assert len(raw)==struct.unpack_from('<I',raw,4)[0]and sum(raw)%256==0
assert raw[:4]==b'OAPF'and raw[16:24]==b'G119PFLT'
text=raw[36:].replace(b'\r\n',b'\n');assert all(c==10 or 32<=c<=126 for c in text);text=text.decode('ascii')
assert text.startswith('OPEN-ADSP-PREFLIGHT G134 version=1\ninput_sha256=ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882\n')
suffix=re.findall(r'^DSP_start=guarded_one_use PIL_request_count=([0-2])$',text,re.M);assert len(suffix)==1 and int(suffix[0])==r['PIL_requests']
final=re.findall(r'^FINAL file_status=(.*?) memory_status=(.*?) cleanup_status=(.*?) truncated=([01])$',text,re.M);assert len(final)==1 and final[0][3]=='0'
files=re.findall(r'^file ([0-9]+) ([a-z0-9_.]+) bytes=([0-9]+) read=([0-9]+) status=(.*?)$',text,re.M)
files_ok=len(files)==64 and all(int(row[0])==i and row[2]==row[3]and row[4]in ['0','Success']for i,row in enumerate(files))
cross=False
if m.get('ok')and meta.get('PIL_code_verified')and meta.get('SCM_code_verified'):
 if int(r['SCM_slot'],16):
  assert int(r['SCM_slot'],16)==int(meta['SCM_image_base'],16)+int(meta['SCM_table_RVA'],16)+56
  assert int(r['original_method'],16)==int(meta['SCM_image_base'],16)+int(meta['SCM_function_RVA'],16)
  cross=True
if r['PAS_entered_stages']:assert cross and files_ok and meta['preflight_ready']
policy=re.findall(r'^G134_inventory_policy matched=([01]) CPU_permissions=not_queried DMA_ownership=not_proved$',text,re.M)
assert len(policy)==1
result={'native_G134_firmware_boots':1,'report_valid':True,'OADP_sha256':r['table_sha256'],'OPAS_sha256':meta.get('table_sha256'),'OAPF_sha256':a['sha256'],'source_file_rows':len(files),'source_file_rows_complete':files_ok,'file_memory_cleanup_status':final[0][:3],'inventory_policy_matched':policy[0]=='1','SCM_cross_bound_to_OPAS':cross,'final_status':r['final_status'],'raw_status':r['raw_status'],'flags':r['flags'],'PIL_requests':r['PIL_requests'],'PAS_entered_stages':r['PAS_entered_stages'],'PAS_returned_stages':r['PAS_returned_stages'],'PAS_sequence_accepted':r['PAS_sequence_accepted'],'auth_entered_mask':r['auth_entered_mask'],'auth_accepted_mask':r['auth_accepted_mask'],'hook_stores':r['hook_stores'],'fatal_restore':r['fatal_restore'],'DSP_running_qualified':False,'GLINK_ready_qualified':False,'charging_qualified':False,'partition_flashes':0,'scope':'Native reports, including refusals/partial authentication; inspect every stage before deciding the next action. No automatic retry or shutdown.'}
(p/'native-analysis.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
