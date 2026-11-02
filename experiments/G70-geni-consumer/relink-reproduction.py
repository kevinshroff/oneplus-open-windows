"""Re-link independently compiled objects in fresh host directories; exact PE proof."""
from pathlib import Path
import hashlib,json
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';R=Relay('relink-reproduction.json');s=R.s
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
repro=P/'reproduction-01';assert json.loads((repro/'source-reproduction.json').read_text())['passed']
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
for kind,receipt,oldbase,newbase,objects,binary,expected in [
 ('kernel','link.json',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G70-clock-build-01',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G70-clock-reproduction-01',repro/'kernel-objects','G70-unsigned.sys',P/'G70-unsigned.sys'),
 ('client','client-link.json',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G70-client-build-01',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G70-client-reproduction-01',repro/'client-objects','G70-client.exe',P/'G70-client.exe')]:
 m=json.loads((W/receipt).read_text());compiled=json.loads((objects/'compile.json').read_text())
 op(kind+'-directory','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';$p='"+newbase+"';if(Test-Path -LiteralPath $p){throw 'Preserve existing reproduction'};New-Item -ItemType Directory -Path $p|Out-Null"])
 files=[(objects/row['object'],row['object'],row['sha256'])for row in compiled['objects']]
 if kind=='kernel':
  for row in m['libraries']:assert op(kind+'-shared-lib-'+Path(row['path'].replace('\\','/')).name,'hash',path=row['path'])['sha256']==row['sha256']
 else:
  sdk=W.parent/'clock-owner-G67/private/user-sdk-01';em=json.loads((sdk/'extraction.json').read_text())
  for row in em['files']:
   if row['output'].startswith('lib/'):
    p=sdk/row['output'];files.append((p,p.name,row['sha256']))
 for local,name,h in files:
  assert sha(local)==h
  remote=newbase+'\\'+name
  assert op(kind+'-put-'+name,'put',file=local,path=remote)['sha256']==h
  assert op(kind+'-hash-'+name,'hash',path=remote)['sha256']==h
 argv=[x.replace(oldbase,newbase)for x in m['link_argv']]
 assert op(kind+'-linker','hash',path=argv[0])['sha256']=='7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762'
 op(kind+'-link','exec',argv=argv)
 local=P/('relinked-'+binary)
 r=op(kind+'-retain','get',path=newbase+'\\'+binary,save=local)
 assert sha(local)==r['sha256']==sha(expected)and local.read_bytes()==expected.read_bytes()
 s[kind]={'source_objects':compiled['objects'],'sha256':sha(local),'bytes':local.stat().st_size,'fresh_host_directory':newbase,'whole_PE_byte_identical':True};R.persist()
s.update(passed=True,independent_source_objects_and_both_full_PEs_reproduced=True,native_phone_operations=0);R.persist()
print(json.dumps({k:s[k]for k in ['passed','independent_source_objects_and_both_full_PEs_reproduced','native_phone_operations']}),flush=True)
