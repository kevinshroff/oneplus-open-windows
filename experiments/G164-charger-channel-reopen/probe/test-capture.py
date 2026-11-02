"""Actual kernel capture callbacks with the separately tested DSP peer/OS models."""
from pathlib import Path
import argparse,ast,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();w=Path(__file__).resolve().parent;o=a.output.resolve();o.mkdir(exist_ok=False,parents=True)
old=w.parents[1]/'charging-G158/probe/test-capture.py';tree=ast.parse(old.read_text());pre=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='pre'for t in n.targets)))
pre=pre[:pre.index('static void put32')].replace('G158','G164').replace('g158','g164').replace('G164_SLOTS','G158_SLOTS').replace('G164FindSlots','G158FindSlots')
pre=pre.replace('Time+=ForcedElapsed?30000000:10','Time+=ForcedElapsed?100000000:10')
peer=(w/'test-core.c').read_text();typedef=peer[peer.index('typedef struct'):peer.index('static unsigned Cases;')]
names=['U16','U32','P16','P32','H','Enqueue','ShortRx','Intent','Payload','PickRx','Reply','FailNow','Kick']
def function(source,name):
 m=re.search(r'^static [^\n]+\b'+name+r'\(',source,re.M);assert m,name
 at=source.index('{',m.end())+1;depth=1
 while depth:depth+=(source[at]=='{')-(source[at]=='}');at+=1
 return source[m.start():at]
peer=typedef+'\n'.join(function(peer,n)for n in names)
for name in ['MODEL',*names]:peer=re.sub(r'\b'+name+r'\b','Peer_'+name,peer)
bridge=r'''
static Peer_MODEL Peer;
static void KeMemoryBarrier(void){
 __sync_synchronize();
 if(Mutation&&!MutationDone&&MapCalls==3&&Out->Slots.Descriptor){MutationDone=1;Part[4]^=1;}
 if(Irq[3]){
  assert(Irq[3]==0x30000);Irq[3]=0;Doorbells++;
  memcpy(Peer.D,Part+Locations.Descriptor,32);memcpy(Peer.Tx,Part+Locations.Tx,16384);memcpy(Peer.Rx,Part+Locations.Rx,16384);
  assert(Peer_Kick(&Peer));
  Peer_P32(Part+Locations.Descriptor,Peer.D[0]);Peer_P32(Part+Locations.Descriptor+12,Peer.D[3]);memcpy(Part+Locations.Rx,Peer.Rx,16384);
 }
}
static NTSTATUS KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-50000);Time+=50000;Delays++;return DelayFail?-1:0;}
'''
source=(w/'g164_driver.c').read_text();body=source[source.index('static int ReservedRam'):source.index('VOID G164Control')]
main=r'''
static void File(const char*path,void*b,size_t n){FILE*f=fopen(path,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF);fclose(f);}
static void Save(const char*folder,const char*name){char path[4096];int n=snprintf(path,sizeof(path),"%s/%s",folder,name);assert(n>0&&(size_t)n<sizeof(path));FILE*f=fopen(path,"wbx");assert(f&&fwrite(Out,1,sizeof(*Out),f)==sizeof(*Out));fclose(f);}
static void Reset(void){
 memset(Out,0,sizeof(*Out));memcpy(Fdt,OriginalFdt,sizeof(Fdt));memcpy(Toc,OriginalToc,sizeof(Toc));memcpy(Part,OriginalPart,sizeof(Part));memset(Irq,0,sizeof(Irq));memset(Ranges,0,sizeof(Ranges));memset(&Peer,0,sizeof(Peer));Peer.State=&Out->State;Peer.RemoteCid=9;
 MapCalls=Unmaps=FailMap=CancelAt=CancelChecks=NoRanges=Doorbells=DelayFail=Mutation=MutationDone=ForcedElapsed=Delays=0;G164Maps=G164Fault=G164Ready=0;FullOS=FirmwareMatch=PeerMode=1;Processors=8;Build=26100;Irql=AckFirst=AppendOpen=0;Time=0;
 assert(G158FindSlots(Part,sizeof(Part),&Locations));
}
static void Check(ULONG code,ULONG maps){Capture(Out,(void*)1,0x1234);assert(Out->Code==code&&MapCalls==maps&&Unmaps==maps&&Out->Nonce==0x1234&&G164Ready);assert((G164Fault!=0)==(code!=0));if(code<2000&&code)assert(!Doorbells&&!Out->State.TxWriteAttempts);}
int main(int argc,char**argv){
 assert(argc==5);unsigned cases=0;Out=calloc(1,sizeof(*Out));assert(Out);File(argv[1],OriginalFdt,sizeof(OriginalFdt));File(argv[2],OriginalToc,sizeof(OriginalToc));File(argv[3],OriginalPart,sizeof(OriginalPart));
 for(unsigned mode=0;mode<4;mode++){
  Reset();Peer.Order=mode&1;Peer.Fragment=(mode>>1)&1;Peer.RemoteClose=1;Check(0,4);
  assert(Out->State.Complete&&Out->State.CloseAcked&&Out->State.RemoteClosed&&Out->State.RepliesMask==1023&&Peer.Queries==10&&Out->State.Battery.ValueValidMask==1023&&Doorbells==Out->State.KickAttempts);
  if(!mode)Save(argv[4],"success-batch.bin");cases++;
 }
 Reset();Peer.AckOnly=1;Check(2012,4);assert(Out->State.OpenAcked&&!Out->State.RemoteOpenSeen&&!Out->State.QueriesSentMask&&!Out->State.IntentsAdvertised&&Out->State.CloseAcked&&Peer.ChannelClosed&&Out->State.TxFrames==2&&Out->State.RxFrames==2);Save(argv[4],"ack-only-closed.bin");cases++;
 for(unsigned i=1;i<=4;i++){Reset();FailMap=i;Capture(Out,(void*)1,0x1234);assert(Out->Code&&MapCalls==i&&Unmaps==i-1&&!Doorbells&&!Out->State.TxWriteAttempts);cases++;}
 for(unsigned i=0;i<5;i++){Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;if(i==4)Irql=1;Check(1001,0);cases++;}
 for(unsigned i=0;i<6;i++){Reset();Ranges[0].BaseAddress.QuadPart=(LONGLONG[]){0x400000,0x407800,0x81a00000,0x81cfffff,0x81d00000,0x81eff800}[i];Ranges[0].NumberOfBytes.QuadPart=4096;Check(1002,0);cases++;}
 Reset();NoRanges=1;Check(1002,0);cases++;
 Reset();Fdt[0]^=1;Check(1004,1);Save(argv[4],"refused-FDT.bin");cases++;
 Reset();Toc[0]^=1;Check(1006,2);cases++;
 Reset();Part[32]^=1;Check(1008,3);cases++;
 Reset();Mutation=1;Check(1008,3);assert(MutationDone);cases++;
 Reset();CancelAt=1;Check(1010,4);assert(Out->Cancelled);cases++;
 Reset();CancelAt=2;Check(0,4);assert(CancelChecks==1&&Out->State.Complete);cases++;
 Reset();ForcedElapsed=1;Check(3001,4);assert(Out->TimedOut&&!Doorbells&&!Out->State.Started);cases++;
 Reset();Peer.Silent=1;Check(2012,4);assert(Out->TimedOut&&!Out->State.Complete&&Out->State.CloseAcked&&Peer.ChannelClosed&&Delays>1500);Save(argv[4],"timeout-closed.bin");cases++;
 Reset();DelayFail=1;Capture(Out,(void*)1,0x1234);assert(Out->Code==1011&&MapCalls==4&&Unmaps==4&&!Out->State.Complete);cases++;
 Reset();Peer.BadReply=2;Check(2009,4);assert(!Out->State.Complete&&Out->State.CloseAcked&&Peer.ChannelClosed);Save(argv[4],"bad-reply-closed.bin");cases++;
 Reset();Peer.ServiceReject=1;Check(0,4);assert(Out->State.Battery.ServiceRejectedMask==768&&Out->State.Battery.ValueValidMask==255);Save(argv[4],"extensions-rejected.bin");cases++;
 Reset();Peer_P32(Part+Locations.Descriptor+4,696);Check(2003,4);assert(!Doorbells&&!Out->State.TxWriteAttempts);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_kernel_capture_callbacks\":true,\"native_operations\":0}\n",cases);free(Out);return 0;
}
'''
# Fixtures combine actual retained G156 metadata with the exact later G159 acknowledged closed
# transport state. This is explicit model RAM, not a new native observation.
raw=(w.parents[1]/'charging-G156/private/native-capture.bin').read_bytes();rows=json.loads((w.parents[1]/'charging-G156/private/decoded-native-r2.json').read_text())['regions']
for index,name in [(1,'toc.bin'),(3,'part.bin')]:
 row=rows[index];b=raw[288+row['offset']:288+row['offset']+row['bytes']];(o/name).write_bytes(b)
latest=(w.parents[1]/'charging-G159/private/native-capture.bin').read_bytes();assert hashlib.sha256(latest).hexdigest()=='376201d802ff404ecfd4c6fea0485f812a89d2829e7538a4eaafd3f56836bab3'
descriptor,tx,rx,items,free=struct.unpack_from('<5I',latest,168);part=bytearray((o/'part.bin').read_bytes());part[descriptor:descriptor+32]=latest[48436:48468];part[tx:tx+16384]=latest[48468:64852];part[rx:rx+16384]=latest[64852:81236];(o/'part.bin').write_bytes(part)
fdt=(w.parents[1]/'charging-G108/private/inspection-r2/boot-data-0x4000.dtb').read_bytes();(o/'fdt.bin').write_bytes(fdt+bytes(0x10000-len(fdt)))
(o/'model.c').write_text(pre+peer+bridge+body+main)
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w),str(o/'model.c'),str(w/'g164_core.c'),str(w/'g164_codec.c'),'-o',str(o/'test')],capture_output=True,text=True);(o/'compiler.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
q=subprocess.run([str(o/'test'),str(o/'fdt.bin'),str(o/'toc.bin'),str(o/'part.bin'),str(o)],capture_output=True,text=True);(o/'run.txt').write_text(q.stdout+q.stderr);assert q.returncode==0,q.stdout+q.stderr
r=json.loads(q.stdout);r['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in w.iterdir()if p.suffix in ['.c','.h']and not p.name.startswith('test-')};r['models']=['WinPE/DSDT/processor/IRQL status','Physical maps/RAM ranges/cancellation/time','Exact tested peer engine extracted from test-core.c; non-native combined retained G156 metadata/G159 closed-state model RAM'];r['limits']=['No native channel/charger operation. Native qualification remains separate.'];(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
