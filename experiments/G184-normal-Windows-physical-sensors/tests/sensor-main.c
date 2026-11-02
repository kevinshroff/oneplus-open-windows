typedef struct {
 GAUGE_MODEL Gauge;uint64_t Clock;unsigned Reads,Writes,Checks,FailRead,FailWrite,CancelAt;
 unsigned Regress100,TimeCalls;
} BOTH;
static uint32_t*SpmiAt(uint32_t at){for(unsigned i=0;i<5;i++)if(at>=SpmiPages[i]&&at-SpmiPages[i]<4096)return&Mem[i][(at-SpmiPages[i])/4];assert(0);return NULL;}
static int ReadBoth(void*x,uint32_t at,uint32_t*v){BOTH*m=x;if(++m->Reads==m->FailRead)return 0;
 if(G111ReadAllowed(at)){*v=SpmiModelRead(SpmiAt(at));return 1;}
 return GaugeModelRead(&m->Gauge,at,v);
}
static int WriteBoth(void*x,uint32_t at,uint32_t v){BOTH*m=x;if(++m->Writes==m->FailWrite)return 0;
 if(G111WriteAllowed(at,v)){SpmiModelWrite(SpmiAt(at),v);return 1;}
 return GaugeModelWrite(&m->Gauge,at,v);
}
static int AvailableBoth(void*x){BOTH*m=x;m->Checks++;return !m->CancelAt||m->Checks<m->CancelAt;}
static uint64_t NowBoth(void*x){return++((BOTH*)x)->Clock;}
static uint64_t TimeBoth(void*x){BOTH*m=x;m->TimeCalls++;return m->Regress100==m->TimeCalls?1:++m->Clock*10;}
static void DelayBoth(void*x,uint32_t us){assert(us==1||us==20);((BOTH*)x)->Clock+=us;}
static void IntervalBoth(void*x){((BOTH*)x)->Clock+=20000;if(Mutation==1)Mem[1][G111Targets[2].Apid]^=1;if(Mutation==2)Reg[2][6]^=1;}
static void ResetBoth(BOTH*m){memset(m,0,sizeof(*m));GaugeModelReset(&m->Gauge);SpmiReset();m->Clock=100000;
 Reg[0][0]=0x20;Reg[0][3]=2;Reg[2][5]=0xa9;Reg[3][5]=0xab;Reg[4][5]=0xac;
 Reg[2][0x46]=0;Reg[2][0xa0]=0;
}
static unsigned Cases;
static void RunBoth(BOTH*m,S183_RESULT*r){S183_IO io={m,ReadBoth,WriteBoth,AvailableBoth,NowBoth,TimeBoth,DelayBoth,IntervalBoth};S183Capture(&io,11,1,r);Cases++;}
int main(int argc,char**argv){
 BOTH*m=calloc(1,sizeof(*m));S183_RESULT*r=calloc(1,sizeof(*r)),*copy=malloc(sizeof(*copy));assert(m&&r&&copy);S183_READING v;
 ResetBoth(m);RunBoth(m,r);assert(!r->Code&&!r->Uncertain&&!r->ConfigGuard&&!r->GaugeGuard);assert(S183Validate(r,&v)==0&&v.VoltageMv[0]==4000&&v.VoltageMv[1]==3975&&r->Config.Commands==19&&r->Gauge.Commands==46);unsigned writes=m->Writes,checks=m->Checks;
 assert(argc==2);FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r));fclose(f);memcpy(copy,r,sizeof(*copy));
 for(unsigned n=1;n<=writes;n++){ResetBoth(m);m->FailWrite=n;RunBoth(m,r);assert(r->Code&&S183Validate(r,&v));}
 for(unsigned n=1;n<=checks;n++){ResetBoth(m);m->CancelAt=n;RunBoth(m,r);if(!(r->Code&&r->CancelledClean&&!r->Uncertain&&!r->PolicyFault))fprintf(stderr,"cancel=%u code=%u cfg=%u guard=%u gauge=%u before=%u after=%u uncertain=%u policy=%u\n",n,r->Code,r->Config.Code,r->ConfigGuard,r->Gauge.Code,r->Gauge.Before.Code,r->Gauge.After.Code,r->Uncertain,r->PolicyFault);assert(r->Code&&r->CancelledClean&&!r->Uncertain&&!r->PolicyFault);}
 for(unsigned n=1;n<=19;n++){ResetBoth(m);TimeoutAt=n;RunBoth(m,r);assert(r->Code&&r->Uncertain&&!r->GaugeNativeWrites);ResetBoth(m);ErrorAt=n;RunBoth(m,r);assert(r->Code&&!r->GaugeNativeWrites);}
 for(unsigned i=0;i<G111_TARGETS;i++){ResetBoth(m);Mem[1][G111Targets[i].Apid]^=1;RunBoth(m,r);assert(r->Code&&!r->GaugeNativeWrites);}
 for(unsigned i=0;i<2;i++){ResetBoth(m);*At(&m->Gauge,G102Controllers[i].Root+4)^=2;RunBoth(m,r);assert(r->Code&&!r->GaugeNativeWrites);ResetBoth(m);*At(&m->Gauge,0xf100000+G102Controllers[i].Pins[0]*4096)^=4;RunBoth(m,r);assert(r->Code&&!r->GaugeNativeWrites);}
 for(unsigned n=2;n<=4;n++){ResetBoth(m);m->Regress100=n;RunBoth(m,r);assert(r->Code==S183_TIME);}
 /* Completed raw structures are independently refused if the fields or
  * transcript binding are damaged. Output stays wholly invalid/zero. */
 for(unsigned n=0;n<18;n++){memcpy(r,copy,sizeof(*r));
  switch(n){case 0:r->Size--;break;case 1:r->Version++;break;case 2:r->Epoch=0;break;case 3:r->Sequence=0;break;case 4:r->Uncertain=1;break;case 5:r->ConfigEnd100ns=1;break;case 6:r->End100ns+=S183_PAIR_100NS;break;case 7:r->Config.Trace[3].Data0^=1;break;case 8:r->Gauge.Values[1][1]++;break;case 9:r->Gauge.Values[1][9]=101;break;case 10:r->Gauge.Trace[0].Kind=9;break;case 11:r->PolicyFault=1;break;case 12:r->ConfigNativeWrites=18;break;case 13:r->GaugeNativeWrites++;break;case 14:r->Gauge.After.ReadyMask=1;break;case 15:r->Config.Values[0][0]^=1;break;case 16:r->Gauge.Before.PinStableMask=0;break;case 17:r->Gauge.Values[1][7]=0;break;}
  assert(S183Validate(r,&v));S183_READING zero={0};assert(!memcmp(&v,&zero,sizeof(v)));Cases++;
 }
 free(copy);free(r);free(m);printf("{\"passed\":true,\"actual_sensor_cases\":%u,\"fixed_core_sources_unchanged\":false,\"native_operations\":0}\n",Cases);return 0;
}
