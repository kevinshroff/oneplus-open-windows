#!/usr/bin/env python3
"""Compile actual native adapter with explicit WDF/MMIO/peer models."""
import argparse,hashlib,json,pathlib,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--sanitizer',choices=['address,undefined','thread'],default='address,undefined');a=p.parse_args()
w=pathlib.Path(__file__).resolve().parent.parent;o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
peer=(w/'tests/peer.h').read_text();peer=peer[peer.index('typedef struct'):].replace('static unsigned Cases;','')
names=['MODEL','U16','U32','P16','P32','H','Enqueue','ShortRx','Intent','Payload','PickRx','Reply','FailNow','Desc','ReadRx','WriteTx','Publish','Barrier','Kick']
for name in names:peer=re.sub(r'\b'+name+r'\b','Peer_'+name,peer)
driver=(w/'native/driver.c').read_text()
for n in ['ntifs.h','wdf.h','aux_klib.h']:driver=driver.replace('#include <'+n+'>','')
driver=driver.replace('#include "guard.inc"','') # Registry/IRQL is an explicit model; reserved-RAM code stays actual.
binding=(w/'native/binding.h').read_text().replace('static const UCHAR ClnExpectedDsdt','const UCHAR ModelDsdt')
bridge=r'''
static Peer_MODEL Peer;static G158_SLOTS Locations;
static void KeMemoryBarrier(void){
 atomic_thread_fence(memory_order_seq_cst);
 if(MutatePart&&!Mutated&&MapCount==3){Mutated=1;Part[4]^=1;}
 if(Irq[12]){
  uint32_t door;memcpy(&door,Irq+12,4);assert(door==0x30000);memset(Irq+12,0,4);
  memcpy(Peer.D,Part+Locations.Descriptor,32);memcpy(Peer.Tx,Part+Locations.Tx,16384);memcpy(Peer.Rx,Part+Locations.Rx,16384);
  Peer.Now=Clock/10;assert(Peer_Kick(&Peer));memcpy(Part+Locations.Descriptor,Peer.D,4);memcpy(Part+Locations.Descriptor+12,Peer.D+3,4);memcpy(Part+Locations.Rx,Peer.Rx,16384);
 }
}
'''
# The low byte at Irq[12] is zero for0x30000; test the complete register instead.
bridge=bridge.replace('if(Irq[12])','if(Irq[14])')
pre=(w/'tests/native-model.h').read_text()
code=pre+'\n#include "link_core.h"\n#include "slots.h"\n'+binding+peer+bridge+driver+(w/'tests/native-main.c').read_text()
(o/'model.c').write_text(code)
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-multichar','-fsanitize='+a.sanitizer,'-pthread','-I'+str(w/'native'),'-I'+str(w/'link'),str(o/'model.c'),str(w/'link/link_core.c'),str(w/'link/charger_codec.c'),'-o',str(o/'test-native')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compiler.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test-native'),*[str(w/'tests/fixtures'/n)for n in ['fdt.bin','toc.bin','part.bin']],str(o)],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
result=json.loads(r.stdout);result['sanitizer']=a.sanitizer;result['source_sha256']={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for d in ['link','native','tests']for f in sorted((w/d).iterdir())if f.is_file()};result['limits']=['Explicit WDF/MMIO/WinPE identity and asynchronous peer models; not native hardware qualification.','Device lock, timer drain and object lifetime follow cited Microsoft contracts; ARM64 WDK compilation is separate.','Maintained control device is bring-up infrastructure, not a production PnP/power lease.']
(o/'tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k!='source_sha256'},indent=2))
