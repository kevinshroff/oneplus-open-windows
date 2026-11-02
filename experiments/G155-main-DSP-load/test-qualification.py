"""Accept the real G153 prerequisite and refuse older/mixed/corrupted evidence."""
from pathlib import Path
import copy,hashlib,json,shutil,tempfile
from qualification import qualified_dtb
w=Path(__file__).resolve().parent;p=w/'private';actual=w.parent/'charging-G153/private';rows=[]
r=qualified_dtb(actual);assert r['native_G153_verified'];rows.append({'case':'actual-G153','accepted':True})
for label in ['G144','G146']:
 try:qualified_dtb(w.parent/('charging-'+label)/'private')
 except (AssertionError,KeyError,FileNotFoundError):rows.append({'case':'actual-'+label,'refused':True})
 else:raise AssertionError(label+' accepted')
files=['native-analysis.json','G153-boot-intent.json','G153-boot-result.json','native-collection-jobs.json','DSP-native.json','OPAS-native.json','raw-OAPF-native.json','PIL-native.json']
files += ['native-'+s+'.bin'for s in ['OADP','OSER','OPAS','OAPF','OPIL']]
files += [j['label']+'-receipt.json'for j in json.loads((actual/'native-collection-jobs.json').read_text())]
def change_json(root,name,fn):
 f=root/name;v=json.loads(f.read_text());fn(v);f.write_text(json.dumps(v))
cases=[('wrong-source-image','native-analysis.json',lambda v:v.update(source_image_sha256='0'*64)),('AUTH-not-accepted','native-analysis.json',lambda v:v.update(auth_accepted_mask=0)),('DTB-public-failure','native-analysis.json',lambda v:v.update(DTB_public_success=False)),('main-already-entered','native-analysis.json',lambda v:v.update(phase=[3,1])),('serial-restore-failed','native-analysis.json',lambda v:v.update(serial_fatal_restore=True)),('payload-not-hashed','native-analysis.json',lambda v:v['DTB_admission'].update(payload_hashed=False)),('failed-final-check','native-analysis.json',lambda v:v['DTB_admission']['checks'][2].update(complete=False)),('reader-analysis-mismatch','DSP-native.json',lambda v:v['report'].update(DTB_public_success=False)),('mixed-receipt-session','DSP-receipt.json',lambda v:v.update(session='00000000000000000000000000000000')),('unaccepted-boot','G153-boot-result.json',lambda v:v.update(exit_code=1)),('wrong-debugger-owner','G153-boot-intent.json',lambda v:v['result']['debugger'].update(pid=0))]
for label,name,fn in cases:
 with tempfile.TemporaryDirectory()as tmp:
  root=Path(tmp)
  for n in files:shutil.copyfile(actual/n,root/n)
  change_json(root,name,fn)
  try:qualified_dtb(root)
  except (AssertionError,KeyError,ValueError):rows.append({'case':label,'refused':True})
  else:raise AssertionError(label+' accepted')
with tempfile.TemporaryDirectory()as tmp:
 root=Path(tmp)
 for n in files:shutil.copyfile(actual/n,root/n)
 f=root/'native-OADP.bin';b=bytearray(f.read_bytes());b[-1]^=1;f.write_bytes(b)
 try:qualified_dtb(root)
 except AssertionError:rows.append({'case':'damaged-raw-table','refused':True})
 else:raise AssertionError('Damaged raw accepted')
out={'passed':True,'cases':len(rows),'actual_native_G153_positive':True,'synthetic_native_success':False,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['qualification.py','test-qualification.py']},'results':rows,'native_operations':0};(p/'qualification-tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k not in ['source_sha256','results']},indent=2))
