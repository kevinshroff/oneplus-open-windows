"""Resolve every exported overlay path before considering metadata normalization."""
from pathlib import Path
import hashlib,json,struct
from fdtree import Fdt
W=Path(__file__).resolve().parent;S=W.parent/'private/stock-20261021T013645Z'
overlay=Fdt.read(S/'dtbo_a-1.dtb');symbols={n:overlay.strings('/__symbols__',n) for n in overlay.nodes['/__symbols__']}
# Audit local references independently of libfdt's unchecked per-cell update.
local={};local_count=0
for path,props in overlay.nodes.items():
 if path=='/__local_fixups__' or path.startswith('/__local_fixups__/'):
  target=path[len('/__local_fixups__'):] or '/';assert target in overlay.nodes,target
  for n in props:
   for off in overlay.cells(path,n):
    assert n in overlay.nodes[target] and off<=len(overlay.nodes[target][n])-4,(path,n,off)
    local.setdefault((target,n),[]).append(off);local_count+=1
external={};external_count=0
for label in overlay.nodes['/__fixups__']:
 for ref in overlay.strings('/__fixups__',label):
  path,n,off=ref.rsplit(':',2);off=int(off)
  assert path in overlay.nodes and n in overlay.nodes[path] and 0<=off<=len(overlay.nodes[path][n])-4
  assert (path,n,off) not in external;external[(path,n,off)]=label;external_count+=1
results=[]
for index in [1,2]:
 base=Fdt.read(S/f'vendor_boot_a-base-{index}.dtb');bp=base.phandles();op=overlay.phandles();memo={}
 def resolve(path,seen=()):
  assert path.startswith('/fragment@') and '/__overlay__' in path,path
  frag,sep,rel=path.partition('/__overlay__');assert sep and (not rel or rel.startswith('/'))
  if frag in memo:root=memo[frag]
  else:
   assert frag not in seen,('cyclic fragment target',frag)
   props=overlay.nodes[frag]
   if 'target-path' in props:
    values=overlay.strings(frag,'target-path');assert len(values)==1;root=values[0];assert root in base.nodes
   else:
    cells=overlay.cells(frag,'target');assert len(cells)==1;h=cells[0]
    key=(frag,'target',0)
    if key in external:
     label=external[key];values=base.strings('/__symbols__',label);assert len(values)==1
     root=values[0];assert root in base.nodes and base.cells(root,'phandle')==[next(k for k,v in bp.items() if v==root)]
    elif 0 in local.get((frag,'target'),[]):root=resolve(op[h],seen+(frag,))
    else:root=bp[h]
   memo[frag]=root
  return root.rstrip('/')+rel or '/'
 duplicates=[]
 for label,paths in symbols.items():
  assert paths and all(p in overlay.nodes for p in paths),(label,paths)
  targets=[resolve(p) for p in paths]
  if len(paths)>1:duplicates.append({'symbol':label,'source_paths':paths,'resolved_targets':targets,'all_targets_equal':len(set(targets))==1})
 row={'base_index':index,'symbol_properties':len(symbols),'multi_path_symbols':len(duplicates),'all_duplicate_targets_equal':all(x['all_targets_equal'] for x in duplicates),'duplicates':duplicates,'local_reference_cells_checked':local_count,'external_reference_cells_checked':external_count}
 results.append(row)
 print('base',index,'symbols',len(symbols),'multipath',len(duplicates),'all duplicates same target',row['all_duplicate_targets_equal'],flush=True)
 for d in duplicates:
  if not d['all_targets_equal']:print('AMBIGUOUS',json.dumps(d),flush=True)
(W/'symbol-target-audit.json').write_text(json.dumps({'overlay_sha256':hashlib.sha256(overlay.data).hexdigest(),'base_candidates':results,'scope':'static candidate path resolution; no physical bootloader selection inferred'},indent=2)+'\n')
