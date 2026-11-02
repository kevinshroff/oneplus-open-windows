"""Require actual G153 native files and matching job receipts before packaging.

No model-success option and no phone/debugger operation. Source and native
qualification are different: the pending G153 result cannot be manufactured by
the passing G155 component tests.
"""
from pathlib import Path
import base64,hashlib,json,ntpath,re,struct
DTB_IMAGE='29bff9d6f5d7a5403e0f046d64913b3526c1054bbe5464dce70c54c860de00b5'
def qualified_dtb(root):
 p=Path(root);load=lambda n:json.loads((p/n).read_text());sha=lambda b:hashlib.sha256(b).hexdigest()
 r=load('native-analysis.json');assert r.get('native_G153_firmware_boots')==1 and r['report_valid']is True
 intent=load('G153-boot-intent.json');boot=load('G153-boot-result.json');jobs=load('native-collection-jobs.json')
 assert r['source_image_sha256']==DTB_IMAGE and intent['image_sha256']==DTB_IMAGE
 assert intent['phase']=='temporary_boot_command_accepted'and boot['id']==intent['job']and boot['node']=='host'and boot['status']=='ok'and boot['exit_code']==0
 assert json.loads(boot['output'])==intent['result']and intent['result']['phase']=='temporary_boot_command_accepted'
 assert r['DTB_public_success']is True and r['DTB_load_returned']is True and r['stop_before_main']is True
 assert r['PAS_sequence_accepted']is True and r['memory_setup_accepted']is True and r['diagnostic_stop']is True
 assert r['phase']==[3,0]and r['fault']==0 and r['auth_entered_mask']==r['auth_accepted_mask']==1
 assert r['PIL_requests']==1 and r['PAS_entered_stages']==r['PAS_returned_stages']==3
 assert r['final_status']=='0x8000000000000015'and r['flags']==255
 assert r['DTB_admission']['finite_DTB_admission_complete']is True
 assert r['source_file_rows_complete']is True and r['source_file_rows']==64
 assert all(v in ['0','Success']for v in r['file_memory_cleanup_status'])
 assert r['SCM_cross_bound_to_OPAS']is True and r['inventory_policy_matched']is True
 assert r['SCM_method_stores']==r['serial_cache_stores']==2 and not r['SCM_fatal_restore']and not r['serial_fatal_restore']
 assert r['serial_restoration']=='0x0000000000000000'and not r['secure_errors']and r['serial_parser_fault']==0 and r['partition_flashes']==0
 assert len(r['PAS_records'])==3
 for i,v in enumerate(r['PAS_records']):
  assert v['Image']==36 and v['Entered']==v['Returned']==1 and v['OriginalStatus']==v['ReturnedStatus']==v['Refusal']==0 and v['Results'][:2]==[1,0]
  assert v['Command']==[0x42000201,0x42000202,0x42000205][i]
 assert set(r['raw_table_sha256'])=={'OADP','OSER','OPAS','OAPF','OPIL'}
 primary=load('DSP-native.json');assert primary['ok'] and primary['report']['report_valid']
 dr=primary['report'];sr=dr['SCM_error'];mr=load('OPAS-native.json');ar=load('raw-OAPF-native.json');ir=load('PIL-native.json')
 assert dr['stable_double_read']and sr['stable_double_read']and ar['stable_double_read']
 for k in ['DTB_public_success','DTB_load_returned','stop_before_main','PAS_sequence_accepted','memory_setup_accepted','diagnostic_stop','phase','fault','auth_entered_mask','auth_accepted_mask','PIL_requests','PAS_entered_stages','PAS_returned_stages','DTB_admission','raw_status','final_status','flags']:
  assert r[k]==dr[k],('analysis/reader',k)
 assert r['PAS_records']==dr['records']
 encoded={'OADP':dr['raw_table_base64'],'OSER':sr['raw_table_base64'],'OPAS':mr.get('raw_table_base64')or mr['report']['raw_table_base64'],'OAPF':ar['raw_base64'],'OPIL':ir['raw_table_base64']}
 for sig,h in r['raw_table_sha256'].items():
  raw=(p/('native-'+sig+'.bin')).read_bytes();assert sha(raw)==h and raw==base64.b64decode(encoded[sig],validate=True)
  assert len(raw)>=36 and raw[:4]==sig.encode()and struct.unpack_from('<I',raw,4)[0]==len(raw)and sum(raw)%256==0
  if sig in ['OADP','OSER']:assert raw[16:24]==({'OADP':b'G153DSP1','OSER':b'G153SIP1'}[sig]) and struct.unpack_from('<I',raw,24)[0]==153
 assert r['DTB_admission']['payload_hashed']and r['DTB_admission']['payload_matched']and r['DTB_admission']['hash_outcome']==3
 assert r['DTB_admission']['SHA256']=='f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94'
 assert len(r['DTB_admission']['checks'])==3 and all(c['complete']and c['status']=='0x0000000000000000'and c['CPU_pages']==3 and c['AT_queries']==11 and c['MMIO_reads']==43 and c['reason']==0 for c in r['DTB_admission']['checks'])
 expected=['system-root','G153-read-DSP.exe-put','G128-read-report.exe-put','G132-capture-G131-report.exe-put','G139-read-PIL.exe-put','DSP','OPAS','raw-OAPF','PIL']
 assert len(jobs)==9 and [j['label']for j in jobs]==expected and len({j['job']for j in jobs})==9 and len({j['session']for j in jobs})==1
 session=jobs[0]['session'];assert session not in ['00000000000000000000000000000000','8caf689ed8d9b336c5367a62d9eafe7b']
 for j in jobs:
  receipt=load(j['label']+'-receipt.json');assert receipt['id']==j['job']and receipt['node']=='phone'and receipt['session']==session and receipt['status']=='ok'and receipt['exit_code']==0
  if j['label']in ['DSP','OPAS','raw-OAPF','PIL']:assert json.loads(receipt['output'])==load(j['label']+'-native.json')
 assert load('system-root-receipt.json')['output'].strip().lower()=='x:\\windows'
 debug=intent['result']['debugger'];assert debug['phase']=='G153_fresh_debug_listener'and type(debug['pid'])is int and 0<debug['pid']<2**32
 assert debug['port']==50000 and debug['pipe']=='OpenG80'and debug['task']=='OnePlus-Open-G80-Debug'and debug['task_has_trigger']is False
 assert type(debug['run'])is str and ntpath.isabs(debug['run'])and re.fullmatch(r'[A-Za-z]:\\[A-Za-z0-9 _\\.-]+\\debug\\G153-[0-9]{8}-[0-9]{6}',debug['run'])
 return {'native_G153_verified':True,'native_analysis_sha256':sha((p/'native-analysis.json').read_bytes()),'native_boot_intent_sha256':sha((p/'G153-boot-intent.json').read_bytes()),'image_sha256':DTB_IMAGE,'phone_session':session,'raw_table_sha256':r['raw_table_sha256'],'debugger':debug,'limits':'Qualified DTB public load and pointer restoration only; no global DMA/stage2, production power lease, main DSP, GLINK or charging qualification.'}
