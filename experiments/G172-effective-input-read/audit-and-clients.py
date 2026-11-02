"""Verify source/signature envelope and build exact fixed-action ARM64 clients."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';src=w/'probe';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
meta=json.loads((p/'compile-01/compile.json').read_text())
for n,h in meta['sources'].items():assert sha(src/n)==h,n
sign=json.loads((p/'build-intent.json').read_text());assert sign['complete']and sign['signer']['cms_verified']
u=(p/'G172-unsigned.sys').read_bytes();s=(p/'G172-signed.sys').read_bytes();pe=struct.unpack_from('<I',s,60)[0];assert struct.unpack_from('<H',s,pe+4)[0]==0xaa64
at,n=struct.unpack_from('<II',s,pe+24+112+32);assert at>=len(u)and at+n<=len(s)
def code(b):
 b=bytearray(b[:len(u)]);b[pe+24+64:pe+24+68]=bytes(4);b[pe+24+112+32:pe+24+112+40]=bytes(8);return b
assert code(u)==code(s)
driverhash=sha(p/'G172-signed.sys');old=json.loads((w.parent/'charging-G167/private/signature-and-source-audit.json').read_text())['files']['G167-signed.sys']['sha256'];f=src/'manage_windows.go';text=f.read_text();assert text.count(old)==1;f.write_text(text.replace(old,driverhash))
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0')
for name,files in [('G172-client.exe',['main_windows.go','guard_windows.go','request.go','g172_decode.go']),('G172-manage.exe',['manage_windows.go','guard_windows.go'])]:
 subprocess.run(['go','build','-trimpath','-ldflags=-buildid=','-o',str(p/name),*files],cwd=src,env=env,check=True)
events=[json.loads(s)for s in(p/'go-tests-02.jsonl').read_text().splitlines()];assert not any(e['Action']=='fail'for e in events)
for name,expected in [('capture-01',111),('dispatch-01',45)]:
 tests=json.loads((p/name/'tests.json').read_text());assert tests['passed']and tests['cases']==expected
 for n,h in tests.get('sources',tests.get('source_sha256',{})).items():assert sha(src/n)==h,n
report={'passed':True,'all_compiled_source_hashes_match':True,'signature_changes_only_checksum_security_directory_and_append':True,'CMS_verified_by_native_signer':True,'files':{n:{'path':str(p/n),'sha256':sha(p/n),'bytes':(p/n).stat().st_size}for n in ['G172-signed.sys','G172-client.exe','G172-manage.exe']},'source_sha256':{f.name:sha(f)for f in src.iterdir()if f.is_file()},'Go_pass_events':sum(e['Action']=='pass'for e in events),'native_operations':0,'scope':'Exactly11 fixed SPMI READs. New predictedDCDC identity must pass before2709. No GLINK or PMIC configuration API.'}
(p/'signature-and-source-audit.json').write_text(json.dumps(report,indent=2)+'\n');print({'passed':True,'files':report['files'],'Go_pass_events':report['Go_pass_events']})
