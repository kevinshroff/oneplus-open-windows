"""Link two source-built ARM64 objects using the qualified host linker/libraries."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('link.json');s=R.s;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G70-clock-build-01';oldbase=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G34-build'
assert json.loads((W/'private/clock-model-01/tests.json').read_text())['passed']and json.loads((W/'private/driver-model-01/tests.json').read_text())['passed']
c=json.loads((W/'private/compile-01/compile.json').read_text());assert len(c['objects'])==3 and c['binding_sha256']==sha(W/'private/acpi-01/g70_binding.h')
for name,h in c['headers'].items():assert sha(W/name)==h
for row in c['objects']:assert sha(W/row['source'])==row['source_sha256']and sha(W/'private/compile-01'/row['object'])==row['sha256']
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
op('directory','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+base+"';if(Test-Path -LiteralPath $p){throw 'G70 build directory already exists without this recorded job'};New-Item -ItemType Directory -Path $p|Out-Null"])
paths=[];s['object_inputs']=[];R.persist()
for row in c['objects']:
 p=W/'private/compile-01'/row['object'];remote=base+'\\'+row['object'];assert op('put-'+row['object'],'put',file=p,path=remote)['sha256']==row['sha256'];assert op('hash-'+row['object'],'hash',path=remote)['sha256']==row['sha256'];paths.append(remote);s['object_inputs'].append({'remote':remote,'sha256':row['sha256']});R.persist()
s['libraries']=[];R.persist()
for row in json.loads((W.parent/'platform-G34/link-02.json').read_text())['inputs']:
 if not row['name'].endswith('.lib'):continue
 remote=oldbase+'\\'+row['name'];assert op('lib-'+row['name'],'hash',path=remote)['sha256']==row['sha256'];paths.append(remote);s['libraries'].append({'path':remote,'sha256':row['sha256']});R.persist()
link=r'C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe';assert op('linker','hash',path=link)['sha256']=='7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762';argv=[link,'/machine:arm64','/driver','/entry:FxDriverEntry','/subsystem:native,10.00','/osversion:10.0','/nodefaultlib','/dynamicbase','/nxcompat','/opt:ref','/opt:icf','/Brepro','/incremental:no','/map:'+base+r'\G70.map','/out:'+base+r'\G70-unsigned.sys',*paths];s['link_argv']=argv;R.persist();op('link','exec',argv=argv);p=W/'private/G70-unsigned.sys';r=op('get','get',path=base+r'\G70-unsigned.sys',save=p if not p.exists()else None);assert sha(p)==r['sha256'];s.update(phase='unsigned_ARM64_driver_linked',output_sha256=sha(p));R.persist();print(json.dumps({'phase':s['phase'],'sha256':sha(p),'bytes':p.stat().st_size}))
