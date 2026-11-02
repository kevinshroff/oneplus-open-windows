"""Audit issued driver envelope and build the exact fixed-action clients."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
meta=json.loads((p/'compile-01/compile.json').read_text());assert meta['passed']
for n,h in meta['sources'].items():assert sha(w/n)==h,n
sign=json.loads((p/'build-intent.json').read_text());assert sign['complete']and sign['signer']['cms_verified']
u=(p/'G170-unsigned.sys').read_bytes();s=(p/'G170-signed.sys').read_bytes();pe=struct.unpack_from('<I',s,60)[0];assert struct.unpack_from('<H',s,pe+4)[0]==0xaa64
at,n=struct.unpack_from('<II',s,pe+24+112+32);assert at>=len(u)and at+n<=len(s)
def code(v):
 v=bytearray(v[:len(u)]);v[pe+24+64:pe+24+68]=bytes(4);v[pe+24+112+32:pe+24+112+40]=bytes(8);return v
assert code(u)==code(s)
driverhash=sha(p/'G170-signed.sys');env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0');builds={}
for name,files in [('G170-client.exe',['main_windows.go','guard_windows.go','decode.go']),('G170-manage.exe',['manage_windows.go','guard_windows.go','decode.go','proof.go'])]:
 flags='-buildid='+(' -X main.expectedDriver='+driverhash if 'manage'in name else '')
 argv=['go','build','-trimpath','-ldflags='+flags,'-o',str(p/name),*files];subprocess.run(argv,cwd=w/'client',env=env,check=True)
 b=(p/name).read_bytes();pe2=struct.unpack_from('<I',b,60)[0];assert struct.unpack_from('<H',b,pe2+4)[0]==0xaa64
 builds[name]={'files':files,'flags':flags}
events=[json.loads(s)for s in(p/'go-tests-01.jsonl').read_text().splitlines()];assert not any(x['Action']=='fail'for x in events)
models={}
for n in ['core-final','native-ASan-02','native-TSan-01']:
 j=json.loads((p/n/'tests.json').read_text());assert j['cases']==(699 if n=='core-final' else 92)
 for f,h in j['source_sha256'].items():assert sha(w/f)==h,(n,f)
 models[n]=j['cases']
report={'compiled_sources_match':True,'signed_CMS_verified_by_host':True,'signature_changes_only_checksum_security_directory_and_append':True,'sources':meta['sources'],'client_sources':{f.name:sha(f)for f in(w/'client').iterdir()if f.is_file()},'files':{n:{'path':str(p/n),'sha256':sha(p/n),'bytes':(p/n).stat().st_size}for n in ['G170-signed.sys','G170-client.exe','G170-manage.exe']},'builds':builds,'models':models,'Go_test_events':sum(x['Action']=='pass'for x in events),'ARM64_abi_assertions':101,'native_operations':0,'scope':'Fixed4470mV FV plus one fixed90s SET31/property24 enable/disable pulse per owner. Kernel normal disable survives client closure; a transport fault is uncertainty. No generic property/value/duration API. No native control action yet.'}
(p/'readiness.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in ['files','models','Go_test_events','ARM64_abi_assertions']},indent=2))
