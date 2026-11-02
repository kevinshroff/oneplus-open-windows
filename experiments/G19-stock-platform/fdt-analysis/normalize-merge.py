"""Normalize only equivalent multi-path symbol exports in private derived copies."""
from pathlib import Path
import ctypes as C,hashlib,json,shutil,subprocess
from fdtree import Fdt
W=Path(__file__).resolve().parent;P=W/'private';S=W.parent/'private/stock-20261021T013645Z'
sha=lambda b:hashlib.sha256(b).hexdigest()
audit=json.loads((W/'symbol-target-audit.json').read_text());assert all(r['all_duplicate_targets_equal'] and r['multi_path_symbols']==5 for r in audit['base_candidates'])
original=S/'dtbo_a-1.dtb';before=Fdt.read(original);assert sha(before.data)==audit['overlay_sha256']
# Cross-check every parsed property of all input blobs against the separately
# installed, unmodified libfdt API. This tool never calls its mutation APIs.
lib=C.CDLL('/opt/homebrew/Cellar/dtc/1.8.1/lib/libfdt.1.dylib')
for name,args,result in [('fdt_check_full',[C.c_void_p,C.c_size_t],C.c_int),('fdt_next_node',[C.c_void_p,C.c_int,C.c_void_p],C.c_int),('fdt_get_path',[C.c_void_p,C.c_int,C.c_void_p,C.c_int],C.c_int),('fdt_first_property_offset',[C.c_void_p,C.c_int],C.c_int),('fdt_next_property_offset',[C.c_void_p,C.c_int],C.c_int),('fdt_getprop_by_offset',[C.c_void_p,C.c_int,C.POINTER(C.c_char_p),C.POINTER(C.c_int)],C.c_void_p)]:
 f=getattr(lib,name);f.argtypes=args;f.restype=result
oracle=[]
for path in [original,*[S/f'vendor_boot_a-base-{i}.dtb' for i in [1,2]]]:
 tree=Fdt.read(path);buf=C.create_string_buffer(tree.data);assert lib.fdt_check_full(buf,len(tree.data))==0;found={};off=-1
 while True:
  off=lib.fdt_next_node(buf,off,None)
  if off<0:assert off==-1;break
  dest=C.create_string_buffer(4096);assert lib.fdt_get_path(buf,off,dest,4096)==0
  node=dest.value.decode('ascii');props={};q=lib.fdt_first_property_offset(buf,off)
  while q>=0:
   name=C.c_char_p();n=C.c_int();value=lib.fdt_getprop_by_offset(buf,q,C.byref(name),C.byref(n));assert value and n.value>=0
   props[name.value.decode('ascii')]=C.string_at(value,n.value);q=lib.fdt_next_property_offset(buf,q)
  assert q==-1;found[node]=props
 assert found==tree.nodes
 oracle.append({'file':path.name,'sha256':sha(tree.data),'nodes':len(found),'properties':sum(len(p) for p in found.values()),'all_properties_match_independent_libfdt_walk':True})
normal=[];merged={}
for which,position in [('first',0),('last',-1)]:
 dest=P/f'overlay-symbols-{which}.dtb';assert not dest.exists();shutil.copyfile(original,dest)
 for name in before.nodes['/__symbols__']:
  paths=before.strings('/__symbols__',name)
  if len(paths)>1:subprocess.run(['/opt/homebrew/bin/fdtput','-t','s',str(dest),'/__symbols__',name,paths[position]],check=True)
 after=Fdt.read(dest);assert before.nodes.keys()==after.nodes.keys();changes=[]
 for node,props in before.nodes.items():
  assert props.keys()==after.nodes[node].keys()
  for key,value in props.items():
   if value!=after.nodes[node][key]:
    assert node=='/__symbols__' and len(before.strings(node,key))>1
    assert after.strings(node,key)==[before.strings(node,key)[position]];changes.append(key)
 assert len(changes)==5
 normal.append({'choice':which,'file':str(dest),'sha256':sha(after.data),'changed_symbol_properties':changes,'all_other_nodes_and_properties_byte_identical':True})
 for i in [1,2]:
  output=P/f'kalama-candidate-{i}-{which}.dtb';assert not output.exists()
  a=subprocess.run(['/opt/homebrew/bin/fdtoverlay','-i',str(S/f'vendor_boot_a-base-{i}.dtb'),'-o',str(output),str(dest)],capture_output=True,text=True)
  assert a.returncode==0,a.stderr
  tree=Fdt.read(output);merged[i,which]=(tree,output)
for i in [1,2]:
 a,pa=merged[i,'first'];b,pb=merged[i,'last'];assert a.nodes==b.nodes
 subprocess.run(['/opt/homebrew/bin/dtc','-I','dtb','-O','dts','-o',str(pa.with_suffix('.dts')),str(pa)],check=True,stdout=subprocess.DEVNULL,stderr=(P/f'kalama-candidate-{i}.dtc.log').open('w'))
 result={'base_index':i,'merged_first_sha256':sha(a.data),'merged_last_sha256':sha(b.data),'full_binary_identical':a.data==b.data,'all_nodes_and_property_values_identical':True,'node_count':len(a.nodes),'property_count':sum(len(x) for x in a.nodes.values()),'merged_file':str(pa),'scope':'statically composed stock candidate after equivalent symbol metadata normalization; physical Android selection unproven'}
 normal.append(result);print(json.dumps(result,indent=2),flush=True)
assert sha(original.read_bytes())==audit['overlay_sha256']
r={'stock_overlay_sha256':audit['overlay_sha256'],'raw_stock_inputs_unchanged':True,'unmodified_libfdt_property_oracle':oracle,'normalizations_and_merges':normal,'phone_raw_writes':0,'algorithm':'each multi-path symbol has one proven final target; choose first or last metadata path, preserve every other property, and run unmodified fdtoverlay'}
(W/'normalization-merge-verification.json').write_text(json.dumps(r,indent=2)+'\n')
