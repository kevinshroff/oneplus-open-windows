"""Link only the small project client with pinned ARM64 SDK import libraries."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('client-link-v5.json');s=R.s
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G67-client-build-05'
c=json.loads((P/'client-objects-05/compile.json').read_text());tests=json.loads((P/'client-policy-01/tests.json').read_text());assert tests['passed']and tests['cases']==79 and not tests['fixture_is_native']
for name,digest in c['headers'].items():assert sha(W/name)==digest
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(P/'client-objects-05'/row['object'])==row['sha256']
assert sha(P/'acpi-02/g67_binding.h')==c['binding_sha256']
extraction=json.loads((P/'user-sdk-01/extraction.json').read_text());assert sha(P/'user-sdk-01/extraction.json')==c['user_sdk_extraction_sha256']
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
op('directory','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'Preserve existing client build'};New-Item -ItemType Directory -Path $p|Out-Null"])
inputs=[(P/'client-objects-05'/row['object'],row['object'],row['sha256'])for row in c['objects']]
for row in extraction['files']:
 if row['output'].startswith('lib/'):
  local=P/'user-sdk-01'/row['output'];assert sha(local)==row['sha256'];inputs.append((local,local.name,row['sha256']))
paths=[];s['inputs']=[];R.persist()
for local,name,digest in inputs:
 remote=base+'\\'+name;assert op('put-'+name,'put',file=local,path=remote)['sha256']==digest;assert op('hash-'+name,'hash',path=remote)['sha256']==digest;paths.append(remote);s['inputs'].append({'name':name,'sha256':digest});R.persist()
link=r'C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe';assert op('linker','hash',path=link)['sha256']=='7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762'
argv=[link,'/machine:arm64','/entry:G67Main','/subsystem:console,6.02','/osversion:6.1','/nodefaultlib','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:icf','/Brepro','/incremental:no','/map:'+base+r'\G67-client.map','/out:'+base+r'\G67-client.exe',*paths];s['link_argv']=argv;R.persist();op('link','exec',argv=argv)
out=P/'G67-client-v5.exe';r=op('retain-client','get',path=base+r'\G67-client.exe',save=out);assert sha(out)==r['sha256'];s.update(phase='small_native_ARM64_client_linked_not_executed',binary_sha256=sha(out),bytes=out.stat().st_size);R.persist();print(json.dumps({k:s[k]for k in ['phase','binary_sha256','bytes']}))
