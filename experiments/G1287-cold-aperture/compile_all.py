"""Local COFF compile only; no SYS link/load or monitor execution."""
from pathlib import Path
import json,subprocess,hashlib
W=Path(__file__).resolve().parent;B=W.parent/'gpu-bv-shadow-G1148';rows=json.loads((W/'build/BASE-COMPILE.json').read_text());out=[];changed=[];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for row in rows:
 a=[x for x in row['argv'] if not x.startswith('-I')];a[1:1]=['-I'+str(W/p) for p in ['source/owner','source','source/broker','reference/runtime','reference/inactive/source']];a[a.index('-c')+1]=str(W/row['source']);dest=W/row['object'];dest.parent.mkdir(parents=True,exist_ok=True);a[a.index('-o')+1]=str(dest);q=subprocess.run(a,capture_output=True,text=True);assert q.returncode==0,(row['source'],q.stderr)
 v=dest.read_bytes();assert v[:2]==b'\x64\xaa';dest.write_bytes(v[:4]+bytes(4)+v[8:]);r={k:row[k] for k in ['target','source','object']};r.update(argv=a,sha256=sha(dest),source_sha256=sha(W/row['source']),exit_code=0,stderr=q.stderr);out.append(r)
 if dest.read_bytes()!=(B/row['object']).read_bytes():changed.append(row['object'])
src=W/'source/owner/scm_set_cp0.S';dest=W/'build/owner/49_scm_set_cp0.obj';a=[rows[0]['argv'][0],'--target=aarch64-pc-windows-msvc','-c',str(src),'-o',str(dest)];q=subprocess.run(a,capture_output=True,text=True);assert q.returncode==0,q.stderr;v=dest.read_bytes();dest.write_bytes(v[:4]+bytes(4)+v[8:]);out.append(dict(target='owner',source=str(src.relative_to(W)),object=str(dest.relative_to(W)),argv=a,sha256=sha(dest),source_sha256=sha(src),exit_code=0,stderr=q.stderr));(W/'build/COMPILE.json').write_text(json.dumps(out,indent=2)+'\n');(W/'build/CHANGED-OBJECTS.json').write_text(json.dumps({'original49_recompiled':True,'additional_assembly_objects':1,'compared_to':'G1148 (G1224 g456 overlay is also changed vs G1148)','changed':changed},indent=2)+'\n')
for t in ['owner','broker']:
 old=(B/'build'/f'{t}.rsp').read_text().splitlines();opts=[x for x in old if x.startswith('/')];libs=[x for x in old if x.endswith('.lib')];objs=[r['object'] for r in out if r['target']==t];(W/'build'/f'{t}.rsp').write_text('\n'.join(opts+objs+libs)+'\n')
print(json.dumps({'coff_objects':len(out),'owner':sum(r['target']=='owner' for r in out),'broker':sum(r['target']=='broker' for r in out),'changed_vs_G1148':changed,'SYS_linked':False,'monitor_calls':0}))
