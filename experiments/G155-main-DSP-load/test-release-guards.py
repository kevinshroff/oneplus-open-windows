"""Verify that the actual unqualified/altered evidence cannot create a release."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,tempfile
from qualification import qualified_dtb
w=Path(__file__).resolve().parent;p=w/'private';rows=[]
assert not(p/'release').exists()and not(p/'G155-main-auth.zip').exists()
for label in ['G144','G146']:
 q=subprocess.run([sys.executable,str(w/'package-release.py'),'--dtb-root',str(w.parent/('charging-'+label)/'private')],capture_output=True,text=True)
 assert q.returncode!=0 and 'qualification.py'in q.stderr and not(p/'release').exists()and not(p/'G155-main-auth.zip').exists()
 rows.append({'case':'actual-'+label,'refused_before_output_creation':True})
with tempfile.TemporaryDirectory()as tmp:
 root=Path(tmp);src=w.parent/'charging-G153/private'
 for n in ['native-analysis.json','G153-boot-intent.json','G153-boot-result.json','native-collection-jobs.json']:
  shutil.copyfile(src/n,root/n)
 f=root/'native-analysis.json';v=json.loads(f.read_text());v['DTB_public_success']=False;f.write_text(json.dumps(v))
 q=subprocess.run([sys.executable,str(w/'package-release.py'),'--dtb-root',str(root)],capture_output=True,text=True)
 assert q.returncode!=0 and 'DTB_public_success' in q.stderr and 'FileNotFoundError' not in q.stderr and not(p/'release').exists()and not(p/'G155-main-auth.zip').exists()
 rows.append({'case':'altered-native-G153','refused_before_output_creation':True})
r={'passed':True,'cases':len(rows),'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['package-release.py','qualification.py','test-release-guards.py']},'results':rows,'native_operations':0,'limits':['Actual G144/G146 and altered evidence are refusal cases. No fabricated positive native prerequisite and no release, staging, debug or phone action occurs.']};(p/'release-guard-tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items()if k not in ['source_sha256','results']},indent=2))
