/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed one-boot transport. CFG0 dev0 plus CFG1 absent-bus sink and BAR-MEM; no endpoint BAR/DMA/BME/MSI/SID writes.
 */
#include "g401_transport.h"
#include "G401ExpectedMcfg.h"
#define DBI UINT64_C(0x60000000)
#define ATU UINT64_C(0x60001000)
#define CFG UINT64_C(0x60100000)
static int Fail(G401_REPORT*R,int E){if(!R->FirstError)R->FirstError=(uint32_t)E;return E;}
static int Read(G401_REPORT*R,const G401_IOPS*I,uint64_t A,uint32_t*V){R->Reads++;int E=I->Read32(I->Context,A,V);return E?Fail(R,E):0;}
static int Write(G401_REPORT*R,const G401_IOPS*I,uint64_t A,uint32_t V){R->WriteAttempts++;int E=I->Write32(I->Context,A,V);return E?Fail(R,E):0;}
#define TRY(X) do{int e=(X);if(e)return Fail(R,e);}while(0)
int G401PrepareBus1Ecam(G401_REPORT*R,const G401_IOPS*I){
 if(!R||!I||!I->Read32||!I->Write32||!I->StallUs)return G401_BAD;
 if(R->Attempted)return G401_NOT_READY;
 R->Attempted=1;R->RetainUntilReset=1;R->Stage=1;
 TRY(Read(R,I,DBI,&R->RootId));
 TRY(Read(R,I,DBI+0x8f8,&R->Version));TRY(Read(R,I,DBI+0x8fc,&R->VersionType));
 TRY(Read(R,I,DBI+0x80,&R->LinkBefore));
 TRY(Read(R,I,CFG,&R->EndpointId));TRY(Read(R,I,CFG+4,&R->CommandBefore));
 if((R->RootId&0xffff)!=0x17cb||R->EndpointId!=0x110717cb||
  (R->CommandBefore&4)||!(R->LinkBefore&(1u<<29)))return Fail(R,G401_NOT_READY);
 /* Upstream does not provide a CFG-shift version capability predicate.
  * Record native release/type; refuse absent/unknown register responses.
  * The actual bit readback PLUS all256 BDF probes below qualify this image.
  */
 /* The source constants are quirk reference points, not an exhaustive
  * release allowlist. Validate the actual version-register encoding only
  * (e.g.560A is 0x3536302a), never infer CFG_SHIFT from this number.
  */
 uint32_t Major=R->Version>>24,Minor=(R->Version>>16)&255U,Patch=(R->Version>>8)&255U;
 if(Major<'1'||Major>'9'||Minor<'0'||Minor>'9'||Patch<'0'||Patch>'9'||
    (R->Version&255U)!=0x2aU)return Fail(R,G401_UNSUPPORTED);
 if(R->VersionType==UINT32_MAX)return Fail(R,G401_UNSUPPORTED);
 R->Stage=2;
 for(uint32_t N=0;N<7;N++)TRY(Read(R,I,ATU+N*4,&R->OldAtu[N]));
 /* Exact predecessor fixedCFG0 configuration; no unowned region replacement. */
 if(R->OldAtu[0]!=4||R->OldAtu[1]!=(1u<<31)||R->OldAtu[2]!=0x60100000||
  R->OldAtu[3]||R->OldAtu[4]!=0x60100fff||R->OldAtu[5]!=0x01000000||R->OldAtu[6])
  return Fail(R,G401_NOT_READY);
 /* Preflight every new slot before ANY mutation. The selected iATU aperture
  * is 4KiB; slots1/2 are within it, but capacity is synthesized. Disabled or
  * exact desired maps only; strict independent readbacks below qualify slots.
  */
 const uint64_t Cfg1Atu=ATU+0x200,MemAtu=ATU+0x400;
 static const uint32_t Cfg1Want[7]={5,0x80000000,0x60108000,0,0x601fffff,0xff000000,0};
 static const uint32_t MemWant[7]={0,0x80000000,0x60300000,0,0x63ffffff,0x60300000,0};
 uint32_t Cfg1Same=1,MemSame=1;
 for(uint32_t N=0;N<7;N++){
  TRY(Read(R,I,Cfg1Atu+N*4,&R->Cfg1Old[N]));
  TRY(Read(R,I,MemAtu+N*4,&R->MemOld[N]));
  if(R->Cfg1Old[N]!=Cfg1Want[N])Cfg1Same=0;
  if(R->MemOld[N]!=MemWant[N])MemSame=0;
 }
 if((R->Cfg1Old[1]&0x80000000U)&&!Cfg1Same)return Fail(R,G401_NOT_READY);
 if((R->MemOld[1]&0x80000000U)&&!MemSame)return Fail(R,G401_NOT_READY);
 /* RootPort source setup_rc programs0/1/1; do not assume inherited bus
  * numbers. Preflight Type1 header and root words before ANY mutation.
  */
 TRY(Read(R,I,DBI+0x0c,&R->RootHeader));
 TRY(Read(R,I,DBI+4,&R->RootCommandBefore));
 TRY(Read(R,I,DBI+0x18,&R->RootBusBefore));
 TRY(Read(R,I,DBI+0x20,&R->RootMemoryBefore));
 if(((R->RootHeader>>16)&0x7fU)!=1U||R->RootCommandBefore==UINT32_MAX||
    R->RootBusBefore==UINT32_MAX||R->RootMemoryBefore==UINT32_MAX)
  return Fail(R,G401_UNSUPPORTED);
 uint32_t Bus=(R->RootBusBefore&0xff000000U)|0x00010100U;
 /* Establish secondary1 BEFORE fallback Type1 transactions to absent busFF.
  * Otherwise a reset/default or inherited secondaryFF could convert the sink
  * into Type0 targeting the real endpoint. Preserve latency byte.
  */
 if(R->RootBusBefore!=Bus)TRY(Write(R,I,DBI+0x18,Bus));
 TRY(Read(R,I,DBI+0x18,&R->RootBusAfter));
 if(R->RootBusAfter!=Bus)return Fail(R,G401_IO);
 R->Stage=3;
 TRY(Write(R,I,ATU+4,0));TRY(Write(R,I,ATU,4));
 TRY(Write(R,I,ATU+8,0x60100000));TRY(Write(R,I,ATU+12,0));
 TRY(Write(R,I,ATU+16,0x60107fff));TRY(Write(R,I,ATU+20,0));TRY(Write(R,I,ATU+24,0));
 /* CFG-shift uses CPU MEM address[27:12] as CFG BDF. Zero target, not
  * predecessor fixedBDF01000000. Only enable+CFG-shift; do not import unrelated
  * upstream ATU_DMA_BYPASS/ECRC fields without matching Open requirements.
  */
 TRY(Write(R,I,ATU+4,(1u<<31)|(1u<<28)));
 for(uint32_t N=0;N<5;N++){
  uint32_t V;R->EnablePolls++;TRY(Read(R,I,ATU+4,&V));
  if((V&((1u<<31)|(1u<<28)))==((1u<<31)|(1u<<28)))break;
  TRY(I->StallUs(I->Context,1000));
 }
 for(uint32_t N=0;N<7;N++)TRY(Read(R,I,ATU+N*4,&R->NewAtu[N]));
 if(R->NewAtu[0]!=4||R->NewAtu[1]!=((1u<<31)|(1u<<28))||
  R->NewAtu[2]!=0x60100000||R->NewAtu[3]||R->NewAtu[4]!=0x60107fff||R->NewAtu[5]||R->NewAtu[6])
  return Fail(R,G401_UNSUPPORTED);
 /* Only functions0..7 of device0 use CFG0. Remaining ECAM device space
  * becomes Type1 directed to absent busFF; an endpoint rejects Type1 withUR.
  * No CFG_SHIFT in this slot. Offset spans less than1MiB, leaving target busFF.
  * Actual CPU all-ones response remains required, not inferred from registers.
  */
 if(R->Cfg1Old[1]&0x80000000U)R->Cfg1UsedExisting=1;
 else{
  TRY(Write(R,I,Cfg1Atu+4,0));
  for(uint32_t N=0;N<7;N++)if(N!=1)TRY(Write(R,I,Cfg1Atu+N*4,Cfg1Want[N]));
  TRY(Write(R,I,Cfg1Atu+4,Cfg1Want[1]));
  for(uint32_t N=0;N<5;N++){uint32_t V;R->Cfg1Polls++;TRY(Read(R,I,Cfg1Atu+4,&V));if(V&0x80000000U)break;TRY(I->StallUs(I->Context,1000));}
 }
 for(uint32_t N=0;N<7;N++){
  TRY(Read(R,I,Cfg1Atu+N*4,&R->Cfg1New[N]));
  if(R->Cfg1New[N]!=Cfg1Want[N])return Fail(R,G401_UNSUPPORTED);
  uint32_t V;TRY(Read(R,I,ATU+N*4,&V));if(V!=R->NewAtu[N])return Fail(R,G401_UNSUPPORTED);
  TRY(Read(R,I,MemAtu+N*4,&V));if(V!=R->MemOld[N])return Fail(R,G401_UNSUPPORTED);
 }
 R->Stage=4;
 for(uint32_t Df=0;Df<256;Df++){
  TRY(Read(R,I,CFG+((uint64_t)Df<<12),&R->Identities[Df]));
  if((!Df&&R->Identities[Df]!=0x110717cb)||(Df&&R->Identities[Df]!=UINT32_MAX))
   return Fail(R,G401_UNSUPPORTED);
 }
 TRY(Read(R,I,CFG+4,&R->CommandAfter));TRY(Read(R,I,DBI+0x80,&R->LinkAfter));
 if((R->CommandAfter&4)||!(R->LinkAfter&(1u<<29)))return Fail(R,G401_NOT_READY);
 R->Stage=5;R->SeparationValid=1;
 /* Windows sees bus1 only; firmware must configure hidden type1 Root Port.
  * Source dw_pcie_setup_rc sets bus numbers/MEM/MASTER; pci_setup_bridge_mmio
  * derives MEMBaseLimit from the same advertised bus window. No endpointCMD.
  */
 uint32_t CurrentBus,CurrentCmd,CurrentMemory;
 TRY(Read(R,I,DBI+0x18,&CurrentBus));
 TRY(Read(R,I,DBI+4,&CurrentCmd));TRY(Read(R,I,DBI+0x20,&CurrentMemory));
 if(CurrentBus!=Bus||(CurrentCmd&0xffffU)!=(R->RootCommandBefore&0xffffU)||CurrentMemory!=R->RootMemoryBefore)
  return Fail(R,G401_NOT_READY);
 if(R->RootMemoryBefore!=0x63f06030U)TRY(Write(R,I,DBI+0x20,0x63f06030U));
 /* Write zeros to upper Status W1C bits; preserve all existing command bits.
  * MEM+MASTER are ROOTPORT permissions, not endpoint BusMaster enable.
  */
 uint32_t Cmd=(R->RootCommandBefore&0xffffU)|6U;
 if((R->RootCommandBefore&6U)!=6U)TRY(Write(R,I,DBI+4,Cmd));
 TRY(Read(R,I,DBI+4,&R->RootCommandAfter));
 TRY(Read(R,I,DBI+0x18,&R->RootBusAfter));
 TRY(Read(R,I,DBI+0x20,&R->RootMemoryAfter));
 if((R->RootCommandAfter&0xffffU)!=Cmd||R->RootBusAfter!=Bus||R->RootMemoryAfter!=0x63f06030U)
  return Fail(R,G401_IO);
 R->RootForwardingValid=1;
 /* Selected CPU/PCI60300000..63ffffff memory moves to slot2. Slot was
  * preflighted before any mutation. Recheck it before replacing disabled map.
  */
 for(uint32_t N=0;N<7;N++){uint32_t V;TRY(Read(R,I,MemAtu+N*4,&V));if(V!=R->MemOld[N])return Fail(R,G401_NOT_READY);}
 if(R->MemOld[1]&0x80000000U)R->MemUsedExisting=1;
 else{
  TRY(Write(R,I,MemAtu+4,0));
  for(uint32_t N=0;N<7;N++)if(N!=1)TRY(Write(R,I,MemAtu+N*4,MemWant[N]));
  TRY(Write(R,I,MemAtu+4,MemWant[1]));
  for(uint32_t N=0;N<5;N++){uint32_t V;R->MemPolls++;TRY(Read(R,I,MemAtu+4,&V));if(V&0x80000000U)break;TRY(I->StallUs(I->Context,1000));}
 }
 /* Independent final readback catches missing/mirrored slots, then repeat
  * all256 BDF checks with final hidden bridge and all3 live regions.
  */
 for(uint32_t N=0;N<7;N++){
  TRY(Read(R,I,MemAtu+N*4,&R->MemNew[N]));if(R->MemNew[N]!=MemWant[N])return Fail(R,G401_UNSUPPORTED);
  uint32_t V;TRY(Read(R,I,ATU+N*4,&V));if(V!=R->NewAtu[N])return Fail(R,G401_UNSUPPORTED);
  TRY(Read(R,I,Cfg1Atu+N*4,&V));if(V!=R->Cfg1New[N])return Fail(R,G401_UNSUPPORTED);
 }
 for(uint32_t Df=0;Df<256;Df++){
  TRY(Read(R,I,CFG+((uint64_t)Df<<12),&R->Identities[Df]));
  if((!Df&&R->Identities[Df]!=0x110717cb)||(Df&&R->Identities[Df]!=UINT32_MAX))return Fail(R,G401_UNSUPPORTED);
 }
 TRY(Read(R,I,CFG+4,&R->CommandAfter));if(R->CommandAfter&4)return Fail(R,G401_NOT_READY);
 R->MemValid=1;R->Stage=6;return 0;
}
static uint32_t U32(const uint8_t*P){return (uint32_t)P[0]|(uint32_t)P[1]<<8|(uint32_t)P[2]<<16|(uint32_t)P[3]<<24;}
int G401BuildMcfg(const G401_REPORT*R,const uint8_t*Old,size_t N,uint8_t*Out,size_t Capacity){
 if(!R||!Old||!Out||Out==Old||Capacity<N||N<60||((N-44)%16))return G401_BAD;
 if(!R->SeparationValid||R->FirstError||R->Stage!=6||!R->MemValid||!R->RootForwardingValid||(R->CommandAfter&4))return G401_NOT_READY;
 if(N!=sizeof(G401ExpectedMcfg))return G401_UNSUPPORTED;
 for(size_t I=0;I<N;I++)if(Old[I]!=G401ExpectedMcfg[I])return G401_UNSUPPORTED;
 if(Old[0]!='M'||Old[1]!='C'||Old[2]!='F'||Old[3]!='G'||U32(Old+4)!=N)return G401_BAD;
 uint8_t Sum=0;for(size_t I=0;I<N;I++)Sum=(uint8_t)(Sum+Old[I]);if(Sum)return G401_BAD;
 size_t Match=0,At=0;
 for(size_t I=44;I<N;I+=16){
  if(!Old[I+8]&&!Old[I+9]){
   if(U32(Old+I)!=0x60000000||U32(Old+I+4)||Old[I+10]!=0||Old[I+11]!=1)return G401_UNSUPPORTED;
   Match++;At=I;
  }
 }
 if(Match!=1)return G401_UNSUPPORTED;
 for(size_t I=0;I<N;I++)Out[I]=Old[I];Out[At+10]=1;Out[9]=0;
 Sum=0;for(size_t I=0;I<N;I++)Sum=(uint8_t)(Sum+Out[I]);Out[9]=(uint8_t)(0-Sum);return 0;
}
