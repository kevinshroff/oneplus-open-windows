/* SPDX-License-Identifier: GPL-2.0-only */
#include "g289_rc0.h"
#include "g200_phy_plan.h"
#define PARF UINT64_C(0x1c00000)
#define PHY UINT64_C(0x1c06000)
#define DBI UINT64_C(0x60000000)
#define ELBI UINT64_C(0x60000f20)
#define ATU UINT64_C(0x60001000)
#define CONF UINT64_C(0x60100000)
typedef struct{G289_RC0*R;const G200_GCC_IO*I;}OPS;
static G200_STATUS Bad(OPS*O,G200_STATUS E){if(!O->R->FirstStatus)O->R->FirstStatus=E;O->R->Uncertain|=O->R->WriteAttempts!=0;return E;}
static G200_STATUS Read(OPS*O,uint64_t A,uint32_t*V){G200_STATUS E=O->I->Read32(O->I->Opaque,A,V);return E?Bad(O,E):0;}
static G200_STATUS Write(OPS*O,uint64_t A,uint32_t V){O->R->WriteAttempts++;G200_STATUS E=O->I->Write32(O->I->Opaque,A,V);return E?Bad(O,E):0;}
static G200_STATUS Mask(OPS*O,uint64_t A,uint32_t Clear,uint32_t Set){uint32_t V;G200_STATUS E=Read(O,A,&V);if(E)return E;return Write(O,A,(V&~Clear)|Set);}
static G200_STATUS Wait(OPS*O,uint32_t Us){G200_STATUS E=O->I->StallUs(O->I->Opaque,Us);return E?Bad(O,E):0;}
#define TRY(X) do{G200_STATUS e=(X);if(e)return Bad(&O,e);}while(0)
G200_STATUS G289RcIdentity(G289_RC0*R,G200_CLOCK_CONTEXT*C,G200_LEASE*L,
 G202_PINS*P,const G200_GCC_IO*I,const G200_GCC_IO*ClockIo,const uint32_t S[2][24]){
 if(!R||!C||!L||!P||!I||!ClockIo||!ClockIo->Read32||!I->Read32||!I->Write32||!I->StallUs)return G200_INVALID;
 if(R->Attempted||!P->Prepared||!P->Active||P->Uncertain||C->Next!=G200_PREPIPE_STEPS)return G200_NOT_READY;
 G200_STATUS E=G200AccessReady(C,L,S,0);if(E)return E;
 R->Attempted=1;R->Stage=1;OPS O={R,I};
 /* Fixed board/source binding and physical admission authorize PARF first.
  * No DBI access is permitted until PARF, PHY, PIPE and PHY-ready complete.
  */
 R->Stage=2;
 /* Fixed source PARF order; preserve unknown inherited RMW fields.
  * Global IRQ masks intentionally remain zero for polling-only diagnostic. */
 TRY(Write(&O,PARF+0x1000,4));TRY(Mask(&O,PARF+0x20,1u<<5,0));
 TRY(Mask(&O,PARF+0x40,1,0));TRY(Write(&O,PARF+0x350,0));
 TRY(Write(&O,PARF,0x365e));TRY(Mask(&O,PARF+0x174,0,1u<<4));
 TRY(Write(&O,PARF+0x22c,0));TRY(Write(&O,PARF+0x508,0));
 TRY(Write(&O,PARF+0x358,0x4000000));TRY(Mask(&O,PARF+0x1a8,0,1u<<31));
 R->Stage=3;
 for(uint32_t N=0;N<G200_PHY_WORD_COUNT;N++){
  TRY(Write(&O,PHY+G200PhySequence[N].Offset,G200PhySequence[N].Value));
  R->PhyWords=N+1;
  if(G200PhySequence[N].DelayUs)TRY(Wait(&O,G200PhySequence[N].DelayUs));
 }
 TRY(Wait(&O,1000)); /* within source995..1005us */
 L->Witnesses|=G200_W_PHY_PROGRAMMED;
 TRY(G200PipeStart(C,L,ClockIo)); /* logical request, no physical completion claim */
 TRY(Read(&O,PHY+0x200,&C->Pipe.SwReset));
 TRY(Read(&O,PHY+0x244,&C->Pipe.Start));
 R->Stage=4;
 for(uint32_t N=0;N<10;N++){
  R->PhyPolls++;TRY(Read(&O,PHY+0x214,&R->PhyStatus));
  G200_STATUS PResult=G200PipePoll(C,L,ClockIo,R->PhyStatus,N==9);
  if(PResult==G200_OK)break;
  if(PResult!=G200_NOT_READY||C->Fault)return Bad(&O,PResult);
  TRY(Wait(&O,1000));
 }
 if((R->PhyStatus&(1u<<6))||C->Next!=G200_RESOURCE_COUNT)return Bad(&O,G200_NOT_READY);
 /* Fresh AON physical admission after PIPE and PHY-ready, before DBI.
  * These exact safe GCC/TLMM addresses already belong to the pre-RC sampler.
  */
 static const uint64_t Aon[24]={0x152020,0x152000,0x152008,0x16b000,0x16b004,0x16b008,
  0x16b01c,0x16b020,0x16b02c,0x16b038,0x16b03c,0x16b048,0x16b054,0x16c000,
  0x16c004,0x16c01c,0xf153000,0xf153004,0xf15e000,0xf15e004,0xf160000,0xf160004,0xf150000,0xf150004};
 uint32_t AfterPipe[2][24];
 for(uint32_t N=0;N<2;N++)for(uint32_t J=0;J<24;J++)TRY(Read(&O,Aon[J],&AfterPipe[N][J]));
 TRY(G200AccessReady(C,L,(const uint32_t(*)[24])AfterPipe,1));
 R->Stage=5;TRY(Wait(&O,10000)); /* selected source ep-latency10ms */
 /* Source's first DBI access is link capability only AFTER PHY-ready.
  * Root ID/class remain diagnostic/validation reads at this now-admitted point.
  * Class is not a bridge-identity gate: source rd_conf synthesizes it.
  */
 TRY(Read(&O,DBI+0x7c,&R->RootLinkCap));
 TRY(Read(&O,DBI,&R->RootId));TRY(Read(&O,DBI+8,&R->RootClass));
 if((R->RootId&0xffff)!=0x17cb||R->RootId==UINT32_MAX||
 (R->RootLinkCap&15)<1||(R->RootLinkCap&15)>4)return Bad(&O,G200_UNSUPPORTED);
 /* Preserve source's distinct clear-veto then set-upscale writes. */
 TRY(Mask(&O,PARF+0x2c4,1,0));TRY(Mask(&O,PARF+0x2c4,0,1u<<8));
 TRY(Mask(&O,DBI+0x714,0,1u<<5));
 /* Fixed PERST release through retained exact TLMM ABI, with pin readback. */
 R->PerstReleased=1;
 E=P->Tlmm->GpioOut(G202PinPacked(94,0,1,1,0),1);if(E){P->Uncertain=1;return Bad(&O,E);}
 uint32_t Pin;TRY(Read(&O,UINT64_C(0xf15e004),&Pin));
 if((Pin&3)!=3)return Bad(&O,G200_DEVICE_ERROR);
 L->Witnesses=(L->Witnesses&~G200_W_PERST_ASSERTED)|G200_W_PERST_RELEASED;
 TRY(Wait(&O,1000));
 R->Stage=6;
 /* OEM's controller PHY settings use source default EQ fields0 and preset
  *55555555; supported generation selects the shadow, fixed Gen1 target limits
  * first training without changing the actual hardware capability fields. */
 TRY(Mask(&O,DBI+0x80c,0x1f00,1u<<8));
 for(uint32_t Gen=3;Gen<=(R->RootLinkCap&15);Gen++){
  TRY(Mask(&O,DBI+0x890,3u<<24,(Gen-3)<<24));
  TRY(Mask(&O,DBI+0x8a8,0xffff00,0));TRY(Mask(&O,DBI+0x890,1,0));
  TRY(Mask(&O,DBI+0x8ac,0x1f,0));
 }
 TRY(Mask(&O,DBI+0x8bc,0,1));
 if((R->RootLinkCap&15)>=3)TRY(Write(&O,DBI+0x154,0x55555555));
 if((R->RootLinkCap&15)>=4)TRY(Write(&O,DBI+0x188,0x55555555)); /*16GT cap168 +LE_CTRL20*/
 TRY(Mask(&O,DBI+0x8bc,1,0));TRY(Mask(&O,DBI+0xa0,15,1));
 TRY(Mask(&O,DBI+0x78,0x7000,0x5000)); /*source PCIE_TLP_RD_SIZE5*/
 TRY(Mask(&O,PARF+0x1b0,0,1u<<8));
 for(uint32_t N=0;N<20;N++){
  TRY(Wait(&O,5000));R->LinkPolls++;
  TRY(Read(&O,ELBI+8,&R->ElbiStatus));TRY(Read(&O,DBI+0x80,&R->LinkStatus));
  if((R->ElbiStatus&0x400)&&(R->LinkStatus&(1u<<29)))break;
 }
 if(!(R->ElbiStatus&0x400)||!(R->LinkStatus&(1u<<29)))return Bad(&O,G200_NOT_READY);
 R->Stage=7;
 /* Source outbound region0, CFG0, bus1/dev0/fn0, fixed4KiB aperture.
  * No BAR window or DMA translation is implied by these CPU config TLPs. */
 TRY(Write(&O,ATU+4,0));TRY(Write(&O,ATU,4));
 TRY(Write(&O,ATU+8,0x60100000));TRY(Write(&O,ATU+12,0));
 TRY(Write(&O,ATU+16,0x60100fff));TRY(Write(&O,ATU+20,0x01000000));
 TRY(Write(&O,ATU+24,0));TRY(Write(&O,ATU+4,1u<<31));
 uint32_t Enabled;TRY(Read(&O,ATU+4,&Enabled));if(!(Enabled&(1u<<31)))return Bad(&O,G200_DEVICE_ERROR);
 TRY(Mask(&O,DBI+0x70c,0,1u<<15));TRY(Write(&O,DBI+0xb40,20));
 for(uint32_t N=0;N<1000;N++){
  R->ConfigPolls++;TRY(Read(&O,CONF,&R->EndpointId));
  if(R->EndpointId&&R->EndpointId!=UINT32_MAX)break;
  TRY(Wait(&O,1000));
 }
 if(!R->EndpointId||R->EndpointId==UINT32_MAX)return Bad(&O,G200_NOT_READY);
 TRY(Read(&O,CONF+4,&R->EndpointCommand));TRY(Read(&O,CONF+8,&R->EndpointClass));
 TRY(Read(&O,CONF+0x2c,&R->EndpointSubsystem));
 /* Unexpected endpoint remains observed data, never a permission to load. */
 if(R->EndpointId!=0x110717cb||(R->EndpointCommand&4))return Bad(&O,G200_UNSUPPORTED);
 R->IdentityValid=1;R->Stage=8;return 0;
}
