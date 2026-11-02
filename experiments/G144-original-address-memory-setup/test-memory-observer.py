from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
f=w.parent/'charging-G136/private/original-SCM-log-01.json';assert hashlib.sha256(f.read_bytes()).hexdigest()=='479282e0391377b6cf6b19387ec56cbba1ae622ec5841d3e8d1633b8b9b96ab6';j=json.loads(f.read_text());assert j['passed']and j['cases']==23
rows=[]
for r in j['results']:
 if r['api_return']is None or r['other_serial_calls']:continue
 rows.append('{%s,%sULL,{%s}}'%(r['command'],r['api_return'],','.join(v+'ULL'for v in r['api_results'])))
(o/'scm-api-fixtures.h').write_text('typedef struct{unsigned Command;unsigned long long Status,Result[4];}SCM_API_FIXTURE;\nstatic const SCM_API_FIXTURE ScmApiFixtures[]={'+','.join(rows)+'};\n')
cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),'-I'+str(o),str(w/'test-memory-observer.c'),str(w/'OpenPasObserver.c'),'-o',str(o/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test')],capture_output=True,text=True);(o/'console.txt').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
out=json.loads(r.stdout);out['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenPasObserver.c','OpenPasObserver.h','test-memory-observer.c']};out['original_fixture_sha256']=hashlib.sha256(f.read_bytes()).hexdigest();(o/'tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
