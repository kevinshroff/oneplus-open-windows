"""Compile a clean source copy and compare all seven ARM64 COFF objects."""
from pathlib import Path
import json,hashlib,subprocess,shutil
w=Path(__file__).resolve().parent;p=w/'private';r=p/'reproduce-01';assert not r.exists();r.mkdir();s=r/'source';s.mkdir()
names=['compile-driver.py','compile-client.py']+[x.name for x in w.glob('g74_*.c')]+[x.name for x in w.glob('g74_*.h')]
for name in names:shutil.copyfile(w/name,s/name)
(s/'binding').mkdir();shutil.copyfile(p/'inputs/g74_binding.h',s/'binding/g74_binding.h')
base=w.parent/'spi-G27/private';common=['--kits',str(base/'wdk-extraction-reproduced'),'--msvc',str(base/'msvc-include'),'--binding',str(s/'binding')]
cmds=[['python3',str(s/'compile-driver.py'),*common,'--output',str(r/'driver')],['python3',str(s/'compile-client.py'),*common,'--user-sdk',str(w.parent/'clock-owner-G67/private/user-sdk-01'),'--output',str(r/'client')]]
rows=[]
for cmd,prior in zip(cmds,['compile-01','client-objects-01']):
 q=subprocess.run(cmd,capture_output=True,text=True);(r/(prior+'-log.txt')).write_text(q.stdout+q.stderr);assert q.returncode==0,(q.stdout,q.stderr)
 out=r/('driver'if prior=='compile-01'else'client');a=json.loads((out/'compile.json').read_text());b=json.loads((p/prior/'compile.json').read_text());assert a['headers']==b['headers']and a['binding_sha256']==b['binding_sha256']
 for x,y in zip(a['objects'],b['objects']):
  assert x['source']==y['source']and x['source_sha256']==y['source_sha256']and x['sha256']==y['sha256'],(x,y)
  rows.append({k:x[k]for k in ('source','source_sha256','object','sha256')})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();report={'passed':True,'clean_source_copy':True,'ARM64_driver_objects':5,'ARM64_client_objects':2,'all_object_hashes_match':True,'objects':rows,'inputs':{n:sha(s/n)for n in names},'binding_sha256':sha(s/'binding/g74_binding.h'),'native_operations':0};(r/'reproduction.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in ('objects','inputs')}))
