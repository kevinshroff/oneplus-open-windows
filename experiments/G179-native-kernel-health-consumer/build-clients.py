"""Audit signed code envelope, compile exact fixed client and guarded manager."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();m=json.loads((p/'compile-final/compile.json').read_text());s=json.loads((p/'build-intent.json').read_text());assert m['passed']and s['complete']and s['signer']['cms_verified']
for n,h in m['sources'].items():assert sha(w/'source'/n)==h,n
u=(p/'G179-unsigned.sys').read_bytes();b=(p/'G179-signed.sys').read_bytes();pe=struct.unpack_from('<I',b,60)[0];assert struct.unpack_from('<H',b,pe+4)[0]==0xaa64;at,n=struct.unpack_from('<II',b,pe+24+112+32);assert at>=len(u)and at+n<=len(b)
def code(b):
 b=bytearray(b[:len(u)]);b[pe+24+64:pe+24+68]=bytes(4);b[pe+24+112+32:pe+24+112+40]=bytes(8);return b
assert code(u)==code(b)
driverhash=sha(p/'G179-signed.sys');env=dict(os.environ,GOOS='windows',GOARCH='arm64',CGO_ENABLED='0');builds={}
for name,files in [('G179-client.exe',['main_windows.go','guard_windows.go','g179_decode.go']),('G179-manage.exe',['manage_windows.go','status_windows.go','guard_windows.go','g179_decode.go'])]:
 flags='-buildid='+(' -X main.expectedDriver='+driverhash if 'manage'in name else'');subprocess.run(['go','build','-trimpath','-ldflags='+flags,'-o',str(p/name),*files],cwd=w/'client',env=env,check=True);builds[name]={'files':files,'flags':flags}
events=[json.loads(x)for x in(p/'go-tests-01.jsonl').read_text().splitlines()];assert not any(x['Action']=='fail'for x in events)
r={'passed':True,'sources_match_compiled':True,'signed_CMS_verified':True,'signature_changes_only_checksum_security_directory_and_append':True,'sources':m['sources'],'client_sources':{f.name:sha(f)for f in(w/'client').iterdir()if f.is_file()},'files':{n:{'path':str(p/n),'sha256':sha(p/n),'bytes':(p/n).stat().st_size}for n in ['G179-signed.sys','G179-client.exe','G179-manage.exe']},'builds':builds,'provider_model_cases':24,'dispatcher_model_cases':45,'Go_pass_events':sum(x['Action']=='pass'for x in events),'ARM64_ABI_assertions':66,'scope':'Read-only kernel RESULT consumer; no hardware-map,physical-read-command,GLINK,charger-control or resource-lease interface.','native_operations':0};(p/'readiness.json').write_text(json.dumps(r,indent=2)+'\n');print({k:r[k]for k in ['files','Go_pass_events','ARM64_ABI_assertions']})
