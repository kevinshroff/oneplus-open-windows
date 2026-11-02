/* SPDX-License-Identifier: GPL-2.0-only
 * Exact FDT AOSS0xc300000/0x400 and IPCC0x408000/client0/signal0.
 * Algorithm references: reference/qcom_aoss.c:138-291;
 * reference/qcom-ipcc.c:153-168, msm_qmp.c:791-820.
 * Policy differences are deliberate: strict range/two-sample checks, no
 * clearing pending length after timeout, no automatic retry or false undo.
 */
#include "g202_qmp.h"
#include "g202_pdc_frames.h"
#define UP UINT32_C(0x0000ffff)
#define DOWN UINT32_C(0xffff0000)
#define MSGRAM UINT64_C(0xc300000)
static G202_STATUS Read(G202_QMP*C,uint32_t O,uint32_t*V){return C->Io.Read32(C->Io.Context,MSGRAM+O,V);}
static G202_STATUS Fail(G202_QMP*C,G202_STATUS E){if(!C->FirstError)C->FirstError=E;C->Uncertain=1;return E;}
static G202_STATUS Write(G202_QMP*C,uint32_t O,uint32_t V){G202_STATUS E=C->Io.Write32(C->Io.Context,MSGRAM+O,V);return E?Fail(C,E):0;}
static G202_STATUS Kick(G202_QMP*C){G202_STATUS E=C->Io.Write32(C->Io.Context,0x40800c,0);return E?Fail(C,E):0;}
static int Range(uint32_t O,uint32_t S){return !(O&3U)&&!(S&3U)&&O>=0x3c&&S>=68&&O<=0x400&&S<=0x400-O;}
static int State(uint32_t S){return S==UP||S==DOWN;}
static int FullyUp(const uint32_t*D){return D[3]==UP&&D[4]==UP&&D[5]==UP&&D[6]==UP&&D[9]==UP&&D[10]==UP&&D[11]==UP&&D[12]==UP;}
static G202_STATUS Sample(G202_QMP*C,uint32_t*D){
 for(uint32_t I=0;I<15;I++){G202_STATUS E=Read(C,I*4,&D[I]);if(E)return E;}
 if(D[0]!=0x4d41494c||D[1]!=1)return G202_ERR(7);
 return 0;
}
G202_STATUS G202QmpInspect(G202_QMP*C){
 if(!C||!C->Io.Read32||C->Uncertain)return G202_ERR(2);
 uint32_t A[15],B[15];G202_STATUS E=Sample(C,A);if(E)return E;E=Sample(C,B);if(E)return E;
 for(uint32_t I=0;I<15;I++)if(A[I]!=B[I])return G202_ERR(6);
 /* Both mailbox ranges stay inside the exact retained0x400 resource and
  * cannot alias each other or the descriptor. */
 if(!Range(B[8],B[7])||!Range(B[14],B[13])||
   (B[8]<B[14]+B[13]&&B[14]<B[8]+B[7]))return G202_ERR(7);
 static const uint8_t States[]={3,4,5,6,9,10,11,12};
 for(uint32_t I=0;I<8;I++)if(!State(B[States[I]]))return G202_ERR(7);
 for(uint32_t I=0;I<15;I++)C->Descriptor[I]=B[I];
 C->Offset=B[14];C->Size=B[13];return 0;
}
static G202_STATUS Wait(G202_QMP*C,uint32_t O,uint32_t V){
 for(uint32_t N=0;N<=1000;N++){
  uint32_t X;G202_STATUS E=Read(C,O,&X);if(E)return Fail(C,E);if(X==V)return 0;
  if(N==1000)break;E=C->Io.Stall(C->Io.Context,1000);if(E)return Fail(C,E);
 }
 return Fail(C,G202_ERR(18));
}
static G202_STATUS Empty(G202_QMP*C){uint32_t L;G202_STATUS E=Read(C,C->Offset,&L);if(E)return E;return L?G202_ERR(6):0;}
G202_STATUS G202QmpOpen(G202_QMP*C){
 if(!C||C->Opened||C->Borrowed||C->ChannelChanged||C->NextFrame||C->Uncertain||!C->Io.Write32||!C->Io.Stall)return G202_ERR(2);
 G202_STATUS E=G202QmpInspect(C);if(E)return E;E=Empty(C);if(E)return E;
 if(FullyUp(C->Descriptor)){C->Opened=1;C->Borrowed=1;return 0;}
 uint32_t*D=C->Descriptor;
 if(D[9]!=DOWN||D[10]!=DOWN||D[11]!=DOWN||D[12]!=DOWN||D[3]!=UP||D[4]!=DOWN||D[5]!=DOWN||D[6]!=DOWN)return G202_ERR(6);
 C->ChannelChanged=1;
 E=Write(C,0x10,D[3]);if(E)return E;E=Write(C,0x24,UP);if(E)return E;
 E=Kick(C);if(E)return E;E=Wait(C,0x28,UP);if(E)return E;
 E=Write(C,0x2c,UP);if(E)return E;E=Kick(C);if(E)return E;E=Wait(C,0x14,UP);if(E)return E;
 E=Write(C,0x18,UP);if(E)return E;E=Kick(C);if(E)return E;E=Wait(C,0x30,UP);if(E)return E;
 E=G202QmpInspect(C);if(E)return Fail(C,E);if(!FullyUp(C->Descriptor))return Fail(C,G202_ERR(7));
 C->Opened=1;return 0;
}
G202_STATUS G202QmpSendNextPdc(G202_QMP*C){
 if(!C||!C->Opened||C->Uncertain||C->Pending||C->NextFrame>=13)return G202_ERR(6);
 uint32_t Offset=C->Offset,Size=C->Size;G202_STATUS E=G202QmpInspect(C);if(E)return Fail(C,E);
 if(C->Offset!=Offset||C->Size!=Size||!FullyUp(C->Descriptor))return Fail(C,G202_ERR(7));
 E=Empty(C);if(E)return E;
 const unsigned char*B=G202PdcFrames[C->NextFrame];
 for(uint32_t I=0;I<64;I+=4){
  uint32_t V=(uint32_t)B[I]|((uint32_t)B[I+1]<<8)|((uint32_t)B[I+2]<<16)|((uint32_t)B[I+3]<<24);
  E=Write(C,C->Offset+4+I,V);if(E)return E;
 }
 C->Pending=1;E=Write(C,C->Offset,64);if(E)return E;
 uint32_t Readback;E=Read(C,C->Offset,&Readback);if(E)return Fail(C,E);
 if(Readback!=64&&Readback!=0)return Fail(C,G202_ERR(7));
 E=Kick(C);if(E)return E;E=Wait(C,C->Offset,0);if(E)return E;
 C->Pending=0;C->NextFrame++;return 0;
}
G202_STATUS G202QmpClose(G202_QMP*C){
 if(!C||!C->Opened||C->Uncertain||C->Pending)return G202_ERR(6);
 G202_STATUS E=Empty(C);if(E)return E;
 if(!C->Borrowed){
  E=Write(C,0x2c,DOWN);if(E)return E;E=Write(C,0x24,DOWN);if(E)return E;E=Kick(C);if(E)return E;
  E=Wait(C,0x30,DOWN);if(E)return E;E=Wait(C,0x28,DOWN);if(E)return E;
 }
 C->Opened=0;return 0;
}
