"""Relink the identical recorder with a symbol map; never replace a phone driver."""
from pathlib import Path
import hashlib,json,re,struct
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'resources-G63'
old=json.loads((B/'link.json').read_text());R=Relay('native-symbol-map.json');s=R.s
root=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads\G66-symbol-map'
args=list(old['link_argv'][1:])
args=[('/out:'+root+r'\G63-unsigned.sys')if a.startswith('/out:')else a for a in args]
args+=['/map:'+root+r'\G63.map']
quote=lambda s:"'"+s.replace("'","''")+"'"
checks=[(r['remote'],r['sha256'])for r in old['object_inputs']]+[(r['path'],r['sha256'])for r in old['libraries']]+[(old['link_argv'][0],'7d80b89e242e2ab4d002c3b3508361a45691a01bd1f4be4d19eb765c8d319762')]
script="$ErrorActionPreference='Stop'\n"
for path,h in checks:script+='if((Get-FileHash -LiteralPath '+quote(path)+' -Algorithm SHA256).Hash.ToLower() -ne '+quote(h)+"){throw 'Pinned build input mismatch'}\n"
script+='$Root='+quote(root)+"\nif(Test-Path -LiteralPath $Root){throw 'Preserve symbol outputs'}\nNew-Item -ItemType Directory -Path $Root|Out-Null\n$Link="+quote(old['link_argv'][0])+"\n$Args=@("+','.join(map(quote,args))+')\n$Log=@(& $Link @Args 2>&1)\n$Code=$LASTEXITCODE\n$Log|Set-Content -LiteralPath (Join-Path $Root "link-log.txt")\nif($Code -ne 0){throw "Link failed: $Code"}\nWrite-Output "Identical-input symbol-map link completed."\n'
p=P/'G66-map-link.ps1';p.write_text(script)
def op(label,action,**kw):
 r=R.op(label,'host',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
assert op('stage-link-script','put',file=p,path=p.name)['sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
op('single-map-link','exec',argv=['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',r'C:\Users\PUBLIC_USER\Downloads\Open-G17\payloads'+'\\'+p.name])
for name in ['G63-unsigned.sys','G63.map']:
 op('retain-'+name,'get',path=root+'\\'+name,save=P/('mapped-'+name))
before=(B/'private/G63-unsigned.sys').read_bytes();after=(P/'mapped-G63-unsigned.sys').read_bytes()
assert before==after,'Link map cannot be trusted without exact image identity'
base=struct.unpack_from('<Q',after,struct.unpack_from('<I',after,0x3c)[0]+48)[0]
symbols={}
for line in (P/'mapped-G63.map').read_text().splitlines():
 m=re.match(r'^\s+\d+:[0-9a-fA-F]+\s+(G63Prepare|G63Release|G63D0Entry|G63D0Exit)\s+([0-9a-fA-F]+)\s',line)
 if m:symbols[m[1]]={'VA':hex(int(m[2],16)),'RVA':hex(int(m[2],16)-base)}
assert len(symbols)==4
s.update(phase='byte_identical_unsigned_recorder_linked_with_exact_symbol_map',unsigned_sha256=hashlib.sha256(after).hexdigest(),signed_sha256=hashlib.sha256((B/'private/G63-signed.sys').read_bytes()).hexdigest(),image_base=hex(base),symbols=symbols,phone_operations=0)
R.persist();print(json.dumps({k:s[k]for k in ['phase','unsigned_sha256','image_base','symbols','phone_operations']}),flush=True)
