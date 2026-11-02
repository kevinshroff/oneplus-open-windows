"""Bind saved G155 results; native authority is established only by the CLI.

Peer consistency and public load success do not establish DSP execution,
GLINK, charging, global ownership or a production power lease.
"""
import base64,hashlib,re,struct
SOURCE_INPUT='ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882'
IMAGE='ccdfa94277975cc37b1f3f316d08a401b3127a93d148226412eecfb02d524a6a'
def table(encoded,signature):
 b=base64.b64decode(encoded,validate=True)
 assert 36<=len(b)<=32768+36 and b[:4]==signature.encode()and struct.unpack_from('<I',b,4)[0]==len(b)and sum(b)%256==0,signature+' header/checksum'
 return b,hashlib.sha256(b).hexdigest()
def diagnose(r):
 s=r['SCM_error'];payload=r['main_payload']
 if r['fatal_restore']or s['fatal_restore']:return'pointer-restoration-failed'
 if r['main_public_success']:return'main-public-load-succeeded'
 if r['main_load_returned']:
  if r['auth_accepted_mask']&2:return'main-public-failed-after-accepted-AUTH'
  if payload['Attempted']and not payload['Complete']:return'main-payload-or-final-admission-refused'
  if r['fault']&1024:return'main-copy-admission-refused'
  if s.get('records')and s['records'][-1]['image_id']==1:return'main-secure-call-failed'
  return'main-sequence-incomplete'
 if r['DTB_public_success']and not r['DTB_public_complete']:return'DTB-public-completion-marker-refused'
 if r['DTB_load_returned']and r['auth_accepted_mask']&1:return'DTB-public-failed-after-accepted-AUTH'
 if r['PIL_requests']:return'DTB-sequence-incomplete'
 return'preflight-refused-before-loader'
def analyze(primary,peers,authority=False,expected_files=None):
 out={'evidence_kind':'native'if authority else'offline-model-or-unattested','native_authority':authority,'capture_consistent':False,'observed_main_public_load':False,'DSP_running_qualified':False,'GLINK_ready_qualified':False,'charging_qualified':False,'global_DMA_stage2_ownership_qualified':False,'production_power_lease_qualified':False,'raw_table_sha256':{},'binding_errors':[]}
 if not primary.get('ok'):
  out.update(primary_decode_error=primary.get('error'),classification='primary-report-refused');return out
 r=primary['report'];s=r['SCM_error'];out.update(primary_diagnostic=diagnose(r),report=r)
 try:
  for sig,encoded,h in [('OADP',r['raw_table_base64'],r['table_sha256']),('OSER',s['raw_table_base64'],s['table_sha256'])]:
   b,d=table(encoded,sig);assert d==h;out['raw_table_sha256'][sig]=d
  assert len(peers)==3 and set(peers)=={'OPAS','OAPF','OPIL'},'all three peer reports required'
  m,a,i=peers['OPAS'],peers['OAPF'],peers['OPIL'];meta=m.get('report',{});inv=i.get('report',{})
  assert m.get('ok')and a.get('ok')and i.get('ok')and a.get('stable_double_read'),'peer reader refused/unstable'
  for sig,encoded,h in [('OPAS',m.get('raw_table_base64')or meta['raw_table_base64'],meta['table_sha256']),('OAPF',a['raw_base64'],a['sha256']),('OPIL',i['raw_table_base64'],i['raw_sha256'])]:
   b,d=table(encoded,sig);assert d==h,sig+' hash';out['raw_table_sha256'][sig]=d
  assert meta['input_sha256']==SOURCE_INPUT and meta['PIL_code_verified']and meta['SCM_code_verified'],'metadata identity'
  assert not inv['memory_eligible']and not inv['DMA_ownership_proved']and not inv['DSP_started'],'inventory promoted ownership/start'
  oapf=base64.b64decode(a['raw_base64'],validate=True);assert oapf[16:24]==b'G119PFLT'
  text=oapf[36:].replace(b'\r\n',b'\n');assert all(c==10 or 32<=c<=126 for c in text)
  text=text.decode('ascii');assert text.startswith('OPEN-ADSP-PREFLIGHT G155 version=1\ninput_sha256='+SOURCE_INPUT+'\n'),'wrong preflight campaign/input'
  assert 'DSP_start=dtb_then_main_auth_diagnostic source_writes=blocked\n'in text
  footer=re.findall(r'^DSP_start=dtb_then_main_auth_diagnostic PIL_request_count=([012])$',text,re.M)
  assert len(footer)==1 and int(footer[0])==r['PIL_requests'],'request count/text differs'
  final=re.findall(r'^FINAL file_status=(.*?) memory_status=(.*?) cleanup_status=(.*?) truncated=([01])$',text,re.M)
  assert len(final)==1 and final[0][3]=='0','missing/truncated preflight'
  files=re.findall(r'^file ([0-9]+) ([a-z0-9_.]+) bytes=([0-9]+) read=([0-9]+) status=(.*?)$',text,re.M)
  out['source_file_rows_complete']=expected_files is not None and len(files)==len(expected_files)==64 and all(int(row[0])==n and row[1]==expected_files[n]['Name']and int(row[2])==expected_files[n]['Bytes']and row[2]==row[3]and row[4]in['0','Success']for n,row in enumerate(files))
  out['file_memory_cleanup_status']=list(final[0][:3])
  if r['PAS_entered_stages']:
   image=int(meta['SCM_image_base'],16)
   assert int(r['SCM_slot'],16)==image+int(meta['SCM_table_RVA'],16)+56 and int(r['original_method'],16)==image+int(meta['SCM_function_RVA'],16),'SCM code/slot binding'
   assert int(s['SCM_image_base'],16)==image and int(s['cache_slot'],16)==image+0xe580,'serial cache binding'
   assert out['source_file_rows_complete']and meta['preflight_ready'],'entered without file/metadata readiness'
   assert 'G144_setup_footprint ready=1 scope=memory_setup_only'in inv['text'],'finite footprint prerequisite'
  returns=re.findall(r'^G155_public_returns DTB=([0-9a-fA-F]+) DTB_marker=([0-9a-fA-F]+) DTB_complete=([01]) main=([0-9a-fA-F]+) main_returned=([01]) main_success=([01]) PRE_POST_direct=not_observed$',text,re.M)
  assert len(returns)==1,'missing public result line'
  v=returns[0];assert [int(v[k],16)for k in [0,1,3]]==[int(r['raw_status']['DTB_PIL'],16),int(r['DTB_marker_status'],16),int(r['raw_status']['main_PIL'],16)]
  assert [int(v[k])for k in [2,4,5]]==[int(r['DTB_public_complete']),int(r['main_load_returned']),int(r['main_public_success'])]
  if r['main_public_success']:
   assert r['PAS_sequence_accepted']and r['phase']==[3,3]and r['auth_accepted_mask']==3 and r['main_payload']['Complete']
   assert r['main_admission']['finite_admission_complete']and r['flags']&127==127
  out.update(capture_consistent=True,classification=out['primary_diagnostic'],observed_main_public_load=authority and r['main_public_success'],native_G155_firmware_boots=int(authority),PRE_POST_directly_observed=False)
 except (AssertionError,KeyError,ValueError,TypeError)as error:
  out.update(classification='inconsistent-or-mixed-capture');out['binding_errors'].append(str(error)or type(error).__name__)
 return out
