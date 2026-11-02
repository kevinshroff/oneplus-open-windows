"""Extract explicit resolved touch/bus resources from normalized stock candidates."""
from pathlib import Path
import hashlib,json
from fdtree import Fdt
W=Path(__file__).resolve().parent
STRING={'compatible','status','reg-names','interrupt-names','clock-names','pinctrl-names','dma-names','regulator-name','chip-name','platform_support_project_commandline','firmware_name','pins','function'}
FIELDS={'compatible','status','reg','reg-names','interrupts','interrupt-parent','interrupt-names','clock-names','pinctrl-names','dma-names','spi-max-frequency','touchpanel,display-coords','touchpanel,panel-coords','touchpanel,tp-index','chip-name','platform_support_project','platform_support_project_dir','platform_support_project_commandline','firmware_name','regulator-name','regulator-min-microvolt','regulator-max-microvolt','regulator-boot-on','regulator-always-on','#address-cells','#size-cells','#gpio-cells','#interrupt-cells','#clock-cells','#dma-cells','#power-domain-cells','qcom,pdc-ranges','gpio-controller','interrupt-controller','pins','function','drive-strength','bias-pull-up','bias-pull-down','bias-disable','output-high','output-low','input-enable'}
records=[]
for i in [1,2]:
 p=W/'private'/f'kalama-candidate-{i}-first.dtb';t=Fdt.read(p);ph=t.phandles()
 def simple(path):
  props=t.nodes[path];r={}
  for n,b in props.items():
   if n not in FIELDS:continue
   if n in STRING:r[n]=t.strings(path,n)
   elif n=='interrupt-parent':r[n]=ph[t.cells(path,n)[0]]
   elif b==b'':r[n]=True
   elif len(b)%4==0:r[n]=t.cells(path,n)
   else:r[n]={'hex':b.hex()}
  return r
 def parents(path):
  while True:
   yield path
   if path=='/':break
   path=path.rsplit('/',1)[0] or '/'
 def status(path):
  out=[]
  for node in parents(path):
   if 'status' in t.nodes[node]:
    v=t.strings(node,'status');assert len(v)==1
    if v[0] not in ['ok','okay']:out.append({'node':node,'status':v[0]})
  return {'enabled_by_static_status':not out,'disabled_ancestors':out}
 def refs(path,key,countkey):
  c=t.cells(path,key);out=[];cur=0
  while cur<len(c):
   h=c[cur];provider=ph[h];cur+=1
   n=t.cells(provider,countkey);assert len(n)==1 and n[0]<=16 and cur+n[0]<=len(c)
   args=c[cur:cur+n[0]];cur+=n[0];out.append({'provider':provider,'args':args,'provider_resources':simple(provider)})
  return out
 def pinctrl(path):
  out={}
  for key in t.nodes[path]:
   if key.startswith('pinctrl-') and key!='pinctrl-names':
    out[key]=[{'node':ph[h],'properties':simple(ph[h]),'children':{n:simple(n) for n in t.nodes if n.startswith(ph[h]+'/')}} for h in t.cells(path,key)]
  return out
 def device(path):
  out={'path':path,'resources':simple(path),'status_chain':status(path),'pinctrl':pinctrl(path),'references':{}}
  for key in t.nodes[path]:
   if key in ['clocks','dmas','power-domains','interconnects']:
    ck={'clocks':'#clock-cells','dmas':'#dma-cells','power-domains':'#power-domain-cells','interconnects':'#interconnect-cells'}[key]
    out['references'][key]=refs(path,key,ck)
   elif key in ['reset-gpio','irq-gpio','enable2v8_gpio','goodix,reset-gpio','goodix,irq-gpio'] or key.endswith('-gpios'):out['references'][key]=refs(path,key,'#gpio-cells')
   elif key.endswith('-supply'):
    cells=t.cells(path,key);assert len(cells)==1;provider=ph[cells[0]];out['references'][key]={'provider':provider,'provider_resources':simple(provider)}
  return out
 touches=[]
 for path,props in t.nodes.items():
  if 'compatible' not in props:continue
  c=t.strings(path,'compatible')
  if any('goodix' in v.lower() for v in c):
   bus=path.rsplit('/',1)[0];touches.append({'touch':device(path),'bus':device(bus),'wrapper':device(bus.rsplit('/',1)[0])})
 # Controllers shared by those devices, including exact PDC/GPIO resources.
 providers=[]
 for path,props in t.nodes.items():
  if 'compatible' in props:
   c=t.strings(path,'compatible')
   if any((('kalama' in v and 'pinctrl' in v) or v in ['qcom,kalama-pinctrl','qcom,kalama-tlmm','qcom,msm-gpio','qcom,kalama-pdc','qcom,pdc','qcom,smem','arm,gic-v3']) for v in c):providers.append(device(path))
 row={'base_index':i,'root_model':t.strings('/','model'),'root_soc_ids':t.cells('/','qcom,msm-id'),'merged_sha256':hashlib.sha256(t.data).hexdigest(),'touch_candidates':touches,'platform_providers':providers}
 records.append(row)
 print('BASE',i,'SoC',row['root_soc_ids'],flush=True)
 for d in touches:
  x=d['touch'];b=d['bus'];print(x['path'],'enabled',x['status_chain']['enabled_by_static_status'],'bus reg',b['resources'].get('reg'),'bus IRQ',b['resources'].get('interrupts'),flush=True)
 for d in providers:print('provider',d['path'],d['resources'].get('compatible'),d['resources'].get('reg'),flush=True)
# Compare resolved resources, excluding only the top-level base/revision fields.
def differences(a,b,path=''):
 if isinstance(a,dict) and isinstance(b,dict):
  for k in sorted(a.keys()|b.keys()):
   if k not in a or k not in b:yield {'path':path+'/'+str(k),'v2':a.get(k),'v1':b.get(k)}
   else:yield from differences(a[k],b[k],path+'/'+str(k))
 elif isinstance(a,list) and isinstance(b,list):
  if len(a)!=len(b):yield {'path':path,'v2':a,'v1':b}
  else:
   for j,(x,y) in enumerate(zip(a,b)):yield from differences(x,y,path+'/'+str(j))
 elif a!=b:yield {'path':path,'v2':a,'v1':b}
diffs=list(differences(records[0]['touch_candidates'],records[1]['touch_candidates'],'touch_candidates'))
print('Resolved touch differences:',json.dumps(diffs,indent=2),flush=True)
r={'scope':'derived static stock candidates; physical selection and actual electrical/controller identity require native evidence','resolved_touch_differences':diffs,'candidates':records,'raw_phone_writes':0}
(W/'touch-platform-resources.json').write_text(json.dumps(r,indent=2)+'\n')
