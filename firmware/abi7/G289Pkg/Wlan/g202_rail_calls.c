/* SPDX-License-Identifier: MIT
 * Exact six source rail names; addresses come from the actual CmdDb protocol,
 * never CPU MMIO or guessed PMIC device indices. No firmware entrypoint.
 */
#include "g202_rpmh_abi.h"
const G202_RAIL_SPEC G202Rails[6]={
 {"vdd-wlan-io","ldob15",1800},{"vdd-wlan","smpg5",1000},
 {"vdd-wlan-aon","smpg2",980},{"vdd-wlan-dig","smpe4",950},
 {"vdd-wlan-rfa1","smpg6",1900},{"vdd-wlan-rfa2","smpg4",1350}
};
G202_STATUS G202ResolveRailAddresses(G202_RAIL_CALLER*C){
 if(!C||C->Client||C->Resolved||!C->CmdDb||C->CmdDb->Version!=0x10000||!C->CmdDb->GetAddress)return G202_ERR(3);
 C->Resolved=0;
 for(uint32_t I=0;I<6;I++){
  uint32_t A=0;C->Trace[I].Attempted=1;
  G202_STATUS E=C->CmdDb->GetAddress(C->CmdDb,G202Rails[I].Resource,&A);
  C->Trace[I].Status=E;C->Trace[I].Address=A;
  if(E)return E;
  /* Exact VRM address namespace/stride for these regulator resources. */
  if(!A||(A&0xffU)||((A>>16)&7U)!=4U||A>0x7ffffU)return G202_ERR(7);
  for(uint32_t J=0;J<I;J++)if(C->Address[J]==A)return G202_ERR(7);
  C->Address[I]=A;
 }
 C->Resolved=1;return 0;
}
G202_STATUS G202CreateRailClient(G202_RAIL_CALLER*C){
 if(!C||C->Client||!C->Resolved||!C->Rpmh||C->Rpmh->Version!=0x10001||
 !C->Rpmh->IsDrvSupported||!C->Rpmh->GetTcsSize||!C->Rpmh->CreateHandle||!C->Rpmh->IssueCommandSet)return G202_ERR(3);
 uint8_t Valid=2;G202_STATUS E=C->Rpmh->IsDrvSupported(2,&Valid);
 if(E)return E;if(Valid!=1)return G202_ERR(7);
 uint32_t Count=UINT32_MAX;E=C->Rpmh->GetTcsSize(2,&Count);
 if(E)return E;if(Count!=16)return G202_ERR(7);
 void*H=NULL;
 /* Fixed lifetime string: the shipped driver retains the name pointer. */
 static const char Name[]="OpenG202-WLAN";
 E=C->Rpmh->CreateHandle(2,Name,0,&H);
 if(E)return E;if(!H)return G202_ERR(7);
 C->Client=H;return 0;
}
G202_STATUS G202BuildRailCommand(const G202_RAIL_CALLER*C,uint32_t I,uint8_t Enable,G202_COMMAND_SET*S){
 if(!C||!C->Resolved||I>=6||Enable>1||!S)return G202_ERR(2);
 *S=(G202_COMMAND_SET){0};
 /* Shipped EFI active set=0; do not copy Linux RPMH_ACTIVE_ONLY_STATE=2. */
 S->Set=0;S->Count=1;S->Command[0].Address=C->Address[I]+(Enable?4U:0U);
 S->Command[0].Data=Enable?1U:G202Rails[I].Millivolts;S->Command[0].Completion=1;
 return 0;
}
G202_STATUS G202IssueXoReference(G202_RAIL_CALLER*C,uint32_t*Address,uint32_t*Id){
 if(!C||!C->Client||!C->CmdDb||C->CmdDb->Version!=0x10000||!C->CmdDb->GetAddress||
    !C->Rpmh||!C->Rpmh->IssueCommandSet||!Address||!Id)return G202_ERR(2);
 uint32_t A=0;C->Trace[6].Attempted=1;
 G202_STATUS E=C->CmdDb->GetAddress(C->CmdDb,"xo.lvl",&A);
 C->Trace[6].Status=E;C->Trace[6].Address=A;if(E)return E;
 if(!A||(A&3U)||((A>>16)&7U)!=3U||A>0x7ffffU)return G202_ERR(7);
 G202_COMMAND_SET S={0};S.Count=1;S.Command[0].Address=A;S.Command[0].Data=3;S.Command[0].Completion=1;
 *Address=A;*Id=UINT32_MAX;E=C->Rpmh->IssueCommandSet(C->Client,&S,Id);
 if(E)return E;return *Id==UINT32_MAX?G202_ERR(7):0;
}
G202_STATUS G202IssueRailCommand(G202_RAIL_CALLER*C,G202_COMMAND_SET*S,uint32_t*Id){
 if(!C||!C->Client||!C->Rpmh||!C->Rpmh->IssueCommandSet||!S||!Id||S->Set!=0||S->Count!=1||S->Command[0].Completion!=1)return G202_ERR(2);
 uint8_t Match=0;
 for(uint32_t I=0;I<6;I++){
  uint32_t A=S->Command[0].Address,D=S->Command[0].Data;
  if((A==C->Address[I]&&D==G202Rails[I].Millivolts)||(A==C->Address[I]+4&&D==1))Match=1;
 }
 if(!Match)return G202_ERR(2);
 *Id=UINT32_MAX;G202_STATUS E=C->Rpmh->IssueCommandSet(C->Client,S,Id);
 if(E)return E;if(*Id==UINT32_MAX)return G202_ERR(7);
 /* RequestID0 can mean redundancy or standalone short-circuit. It is not
  * converted into a successful hardware/completion claim by this primitive. */
 return 0;
}
