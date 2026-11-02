"""Compile the dual-image policy with native DTB INIT/MEM and modeled main/public results.

The firmware adapter, physical memory admission and exact payload hash callback
are not integrated by this test. No native driver, firmware or call is installed.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--native',type=Path,default=w.parent/'charging-G144/private/native-analysis.json')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
j=json.loads(a.native.read_text());assert j['report_valid']and j['memory_setup_accepted']and j['diagnostic_stop']
assert len(j['PAS_records'])==2 and j['PAS_records'][1]['Arguments']==[36,0x9e980000,0x80000]
for r in j['PAS_records']:assert r['OriginalStatus']==0 and r['Results']==[1,0,0,0]
literal=lambda n:hex(n)+'ULL'
(o/'native-API-fixtures.h').write_text('static const unsigned long long NativeStatus[2]={'+
 ','.join(literal(r['OriginalStatus'])for r in j['PAS_records'])+'};\n'+
 'static const unsigned long long NativeResults[2][4]={'+
 ','.join('{'+','.join(map(literal,r['Results']))+'}'for r in j['PAS_records'])+'};\n')
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-fno-omit-frame-pointer','-I'+str(w),'-I'+str(o),str(w/'test-main-sequence.c'),str(w/'OpenPasObserver.c'),'-o',str(o/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test')],capture_output=True,text=True);(o/'console.txt').write_text(r.stdout+r.stderr)
assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()
 for n in ['OpenPasObserver.c','OpenPasObserver.h','test-main-sequence.c','test-main-sequence.py']}
report['native_G144_fixture_sha256']=hashlib.sha256(a.native.read_bytes()).hexdigest()
report['limits']=['Only DTB INIT/MEM fixtures came from native G144; all main/AUTH/public-return results and admission callbacks are modeled.',
 'This is an unintegrated policy candidate, not firmware or memory ownership qualification.']
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
