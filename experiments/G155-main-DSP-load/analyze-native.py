"""Validate the fresh native collector chain and cross-bind all five G155 tables.

Never submits a job or issues a new secure request. Offline fixtures cannot
become native evidence merely by carrying a report's positive boolean fields.
"""
from pathlib import Path
import base64,hashlib,json
from decoder_support import decoder,decode
from analysis_core import analyze,IMAGE,SOURCE_INPUT
w=Path(__file__).resolve().parent;p=w/'private';load=lambda n:json.loads((p/n).read_text())
intent=load('G155-boot-intent.json');assert intent['phase']=='temporary_boot_command_accepted'and intent['image_sha256']==IMAGE
assert intent['DTB_prerequisite_native_verified']is True
boot=load('G155-boot-result.json');assert boot['id']==intent['job']and boot['node']=='host'and boot['status']=='ok'and boot['exit_code']==0
assert json.loads(boot['output'])==intent['result']and intent['result']['phase']=='temporary_boot_command_accepted'
jobs=load('native-collection-jobs.json');assert len(jobs)==9 and len({j['session']for j in jobs})==1
session=jobs[0]['session'];assert session not in [intent['predecessor_phone_session'],'00000000000000000000000000000000']
assert len({j['job']for j in jobs})==9
expected=['system-root','G155-read-DSP.exe-put','G128-read-report.exe-put','G132-capture-G131-report.exe-put','G139-read-PIL.exe-put','DSP','OPAS','raw-OAPF','PIL']
assert [j['label']for j in jobs]==expected
receipts={}
for j in jobs:
 r=load(j['label']+'-receipt.json');assert r['id']==j['job']and r['node']=='phone'and r['session']==session
 assert r['status']in ['ok','error']and r.get('exit_code')in [0,1]
 receipts[j['label']]=r
assert receipts['system-root']['status']=='ok'and receipts['system-root']['exit_code']==0 and receipts['system-root']['output'].strip().lower()=='x:\\windows'
for name in expected[1:5]:assert receipts[name]['status']=='ok'and receipts[name]['exit_code']==0
for label in ['DSP','OPAS','raw-OAPF','PIL']:
 assert json.loads(receipts[label]['output'])==load(label+'-native.json'),'saved JSON differs from actual job receipt'
d=load('DSP-native.json');native=d.get('report',{});serial=native.get('SCM_error',{})
if d.get('ok'):assert native['stable_double_read']and serial['stable_double_read']
primary=decode(decoder(),p/'native-OADP.bin',p/'native-OSER.bin')
if d.get('ok'):
 assert primary['ok']and primary['report']['table_sha256']==native['table_sha256']
 assert primary['report']['SCM_error']['table_sha256']==serial['table_sha256']
peers={sig:load(label+'-native.json')for sig,label in [('OPAS','OPAS'),('OAPF','raw-OAPF'),('OPIL','PIL')]}
capture=(w.parent/'charging-G118/private/firmware-input/capture.json').read_bytes();assert hashlib.sha256(capture).hexdigest()==SOURCE_INPUT
result=analyze(primary,peers,authority=bool(d.get('ok')and native['stable_double_read']and serial['stable_double_read']),expected_files=json.loads(capture)['files'])
for sig,h in result['raw_table_sha256'].items():
 assert hashlib.sha256((p/('native-'+sig+'.bin')).read_bytes()).hexdigest()==h
result.update(source_image_sha256=IMAGE,phone_session=session,collector_job_ids=[j['job']for j in jobs],partition_flashes=0,source='fresh native receipt chain plus independent saved-table decode',native_receipt_chain_valid=True,capture_stable_double_read=bool(d.get('ok')and native['stable_double_read']and serial['stable_double_read']))
(p/'native-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if k!='report'},indent=2))
