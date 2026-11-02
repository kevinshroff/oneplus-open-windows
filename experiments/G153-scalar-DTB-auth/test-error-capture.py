"""Compile real C parser/range tests with original SCM formatter fixtures."""
from pathlib import Path
import argparse,base64,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
fixture=w/'private/original-SCM-log-01.json';j=json.loads(fixture.read_text());assert j['passed']and j['cases']==32
rows=[]
for r in j['results']:
 for line in r['log_writes']:
  text=base64.b64decode(line['text_base64'],validate=True);assert len(text)==line['bytes']<=512
  rows.append('{%d,%d,%d,%dULL,%dULL,{%s}}'%(r['expected_printed_command'],r['expected_printed_status32'],len(text),int(r['api_return'],16),int(r['api_results'][0],16),','.join(str(v)for v in text)))
(o/'original-log-fixtures.h').write_text('typedef struct{unsigned Command,Raw,Bytes;unsigned long long ApiStatus,Result0;unsigned char Text[512];} ORIGINAL_LOG;\nstatic const ORIGINAL_LOG OriginalLogFixtures[]={'+','.join(rows)+'};\n')
args=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(w),'-I'+str(o),str(w/'test-error-capture.c'),str(w/'OpenScmErrorCapture.c'),'-o',str(o/'test')]
r=subprocess.run(args,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test'),str(o/'modeled-OSER-body.bin')],capture_output=True,text=True);(o/'console.txt').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout);report['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['OpenScmErrorCapture.c','OpenScmErrorCapture.h','test-error-capture.c']};report['original_formatter_fixture_sha256']=hashlib.sha256(fixture.read_bytes()).hexdigest();(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
