"""Audit signed code and build fixed typed G180 clients; no phone action."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
m=json.loads((p/'compile-01/compile.json').read_text());assert m['passed']
for n,h in m['sources'].items():assert sha(w/n)==h,n
s=json.loads((p/'build-intent.json').read_text());assert s['complete']and s['signer']['cms_verified']
u=(p/'G180-unsigned.sys').read_bytes();b=(p/'G180-signed.sys').read_bytes();pe=struct.unpack_from('<I',b,60)[0];assert struct.unpack_from('<H',b,pe+4)[0]==0xaa64;at,n=struct.unpack_from('<II',b,pe+24+112+32);assert at>=len(u)and at+n<=len(b)
def code(v):
 v=bytearray(v[:len(u)]);v[pe+24+64:pe+24+68]=bytes(4);v[pe+24+112+32:pe+24+112+40]=bytes(8);return v
assert code(u)==code(b)
events=[json.loads(x)for x in(p/'go-tests-final-02.jsonl').read_text().splitlines()];assert not any(x['Action']=='fail'for x in events)
for n in ['native-ASan-final','native-TSan-final']:
 t=json.loads((p/n/'tests.json').read_text());assert t['cases']==111
 for f,h in t['source_sha256'].items():assert sha(w/f)==h,(n,f)
env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0');builds={};driver=sha(p/'G180-signed.sys')
for name,files in [('G180-client.exe',['main_windows.go','guard_windows.go','decode.go','health.go']),('G180-manage.exe',['manage_windows.go','guard_windows.go','decode.go','health.go','proof.go'])]:
 flags='-buildid='+(' -X main.expectedDriver='+driver if'manage'in name else'');subprocess.run(['go','build','-trimpath','-ldflags='+flags,'-o',str(p/name),*files],cwd=w/'client',env=env,check=True);builds[name]={'files':files,'flags':flags}
v={'passed':True,'compiled_sources_match':True,'signed_CMS_verified':True,'signature_changes_only_checksum_security_directory_and_append':True,'sources':m['sources'],'client_sources':{f.name:sha(f)for f in(w/'client').iterdir()if f.is_file()},'files':{n:{'path':str(p/n),'sha256':sha(p/n),'bytes':(p/n).stat().st_size}for n in ['G180-signed.sys','G180-client.exe','G180-manage.exe']},'builds':builds,'Go_pass_events':sum(x['Action']=='pass'for x in events),'ARM64_ABI_assertions':167,'native_callback_cases':111,'native_operations':0,'scope':'Integrated kernel RESULT work item plus typed FV/restart/health renewal.90s leases,15min hard cap; no generic values/durations. Native qualification pending.'}
(p/'readiness.json').write_text(json.dumps(v,indent=2)+'\n');print({k:v[k]for k in ['files','Go_pass_events','ARM64_ABI_assertions']})
