"""Verify that absent DTB evidence and a genuine older boot cannot activate G151."""
from pathlib import Path
import hashlib,json,subprocess,sys
from qualification import qualified_dtb
w=Path(__file__).resolve().parent;p=w/'private';cases=[]
assert not(p/'release').exists()and not(p/'G151-main-auth.zip').exists()
for name,root,expected in [('pending-G146',w.parent/'charging-G146/private',FileNotFoundError),('actual-G144',w.parent/'charging-G144/private',AssertionError)]:
 try:qualified_dtb(root)
 except expected:cases.append({'case':name,'refused':True})
 else:raise AssertionError('Unqualified native context accepted: '+name)
q=subprocess.run([sys.executable,str(w/'package-release.py')],capture_output=True,text=True)
assert q.returncode!=0 and 'native-analysis.json'in q.stderr and not(p/'release').exists()and not(p/'G151-main-auth.zip').exists()
cases.append({'case':'production-packager-without-prerequisite','refused_before_output_creation':True})
syntax=json.loads((p/'PowerShell-syntax.json').read_text());assert syntax['passed']and syntax['native_Windows_parser']
for n,h in syntax['source_sha256'].items():assert hashlib.sha256((w/n).read_bytes()).hexdigest()==h
report={'passed':True,'cases':len(cases),'native_operations':0,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['qualification.py','package-release.py','Boot-G151-MainAuth.ps1','Refresh-Existing-Debugger.ps1','test-release-guards.py']},'results':cases,'limits':['Genuine G144 data and the still-missing G146 result are refusal cases. No fabricated positive native qualification is used.','Windows PowerShell syntax is verified, but runtime boot/debugger refresh/staging and the successful native qualification path are unexecuted.','No release archive or staging is created while the native prerequisite is missing.']}
(p/'release-guard-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
