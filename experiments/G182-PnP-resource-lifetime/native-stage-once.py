"""Stage and qualify the new namespace on a fresh WinPE boot,then load one fixed PnP package."""
from pathlib import Path
import base64,hashlib,json,sqlite3,time
from ops import q,good,lab,OLDPHONE,P
w=Path(__file__).resolve().parent;p=P;f=p/'native-stage.json';assert not f.exists(),'Observe same saved native operations'
b=json.loads((p/'fresh-boot-intent.json').read_text());assert b['phase']=='temporary_boot_command_accepted'
with sqlite3.connect(lab.STATE/'queue.sqlite3')as c:
 row=c.execute("select session,seen,info from nodes where node='phone'").fetchone();assert row and row[0]!=OLDPHONE and time.time()-row[1]<15
 session=row[0];info=json.loads(row[2]);assert info['os']=='windows'and info['arch']=='arm64'
s={'session':session,'previous_session':OLDPHONE,'created':time.time(),'phase':'staging','partition_flashes':0,'hardware_producer_actions':0};save=lambda:f.write_text(json.dumps(s,indent=2)+'\n');save()
files=json.loads((p/'release-source-files.json').read_text());base='X:\\OpenG17\\payloads\\'
def call(label,argv,timeout=20):return good(q(label,'phone',session=session,argv=argv,timeout=timeout))
for n in ['G155-read-DSP.exe','G154-install-arm64.exe','G182-status.exe','OpenG182.inf','OpenG182.sys','OpenG182.cat','G182-public.cer']:
 v=files[n];local=Path(v['path']);assert hashlib.sha256(local.read_bytes()).hexdigest()==v['sha256'];good(q('native-put-'+n,'phone','put',session=session,file=local,path=n,timeout=25))
v=json.loads(call('fresh-DSP-report',[base+'G155-read-DSP.exe'])['output']);r=v['report'];assert v['ok']and r['report_valid']and r['stable_double_read']and r['flags']==255 and r['phase']==[3,3]and r['PAS_sequence_accepted']and r['DTB_sequence_accepted']and r['main_public_success']and r['main_enabled']and not r['fatal_restore']and not r['fault']and r['hook_stores']==2 and r['PAS_entered_stages']==r['PAS_returned_stages']==6
scm=r['SCM_error'];assert scm['report_valid']and scm['stable_double_read']and not scm['fatal_restore']and scm['hook_stores']==2 and not scm['parser_fault']
raw=base64.b64decode(r['raw_table_base64'],validate=True);assert len(raw)==9116 and raw[:4]==b'OADP'and hashlib.sha256(raw).hexdigest()==r['table_sha256'];(p/'fresh-OADP.bin').write_bytes(raw);(p/'fresh-DSP-report.json').write_text(json.dumps(v,indent=2)+'\n')
v=json.loads(call('postboot-loader-inspect',[base+'G154-install-arm64.exe','inspect'])['output']);assert v['phase']=='G154_inspect'
v=call('native-namespace-before',[r'X:\Windows\System32\pnputil.exe','/enum-devices','/deviceid',r'ACPI\OPEN0182','/resources','/services','/stack']);text=v['output'];assert text.count('ACPI\\OPEN0182\\1')==1,text[:2000];s.update(phase='fresh_DSP_and_namespace_verified');save()
v=call('native-load-PnP',[r'X:\Windows\System32\drvload.exe',base+'OpenG182.inf'],timeout=35);s.update(phase='drvload_returned');save()
v=json.loads(call('native-first-status',[base+'G182-status.exe'])['output']);assert v['ok'];a=v['status'];assert a['MapCalls']==20 and a['UnmapCalls']==a['ReleaseCalls']==0 and a['D0Epoch']==a['PrepareEpoch']==1 and a['ProducerQualified']==0
(p/'native-first-status.json').write_text(json.dumps(v,indent=2)+'\n');v=call('native-namespace-after',[r'X:\Windows\System32\pnputil.exe','/enum-devices','/deviceid',r'ACPI\OPEN0182','/resources','/services','/stack']);s.update(phase='native_PnP_resource_owner_started',initial=a,completed=time.time());save();print({'session':session,'maps':a['MapCount'],'D0':a['D0Active'],'producer_qualified':a['ProducerQualified']})
