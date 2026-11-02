
static unsigned Cases,CyclesTested;
static G96_TRIAL_RESULT T,Saved;
static void Send(G96_PWR_CONTEXT*c,const G96_WIRE_RESULT*f){
 unsigned words=((f->Kind==G96_WIRE_CLEAR?6:f->Payload+8)+3)/4;
 for(unsigned i=0;i<words;i++){uint32_t word=0;for(unsigned j=0;j<4;j++)word|=(uint32_t)f->Tx[i*4+j]<<(j*8);unsigned before=Writes;assert(!G96PowerWrite(c,0xa90700,word^1)&&Writes==before);assert(G96PowerWrite(c,0xa90700,word));Cases+=2;}
}
static void MemoryIdle(void){memset(Memory,0,sizeof(Memory));Memory[14][0x610/4]=0x80;Memory[14][0x614/4]=0x7fc0007f;}
static void Init(G96_PWR_CONTEXT*c,unsigned limit){memset(c,0,sizeof(*c));T=Saved;memset(T.Touch.PollFrames,0,sizeof(T.Touch.PollFrames));T.Touch.PollFrameCount=0;T.Touch.Poll.Limit=limit;T.Touch.Poll.Cycles=0;T.Touch.BusQuiescent=1;c->Trial=&T;c->Result=&T.Power;c->Stream=&Stream;for(unsigned i=0;i<16;i++)c->Maps[i]=Memory[i];c->CommandUsed=4;c->ActiveWords=c->FifoWords=9;c->ActiveRead=1;c->ActiveBytes=34;c->ActiveAddress=0x10274;c->ClearUsed=1;MemoryIdle();}
static void OneWire(G96_PWR_CONTEXT*c,const G96_WIRE_RESULT*from,unsigned start,unsigned cycle){
 unsigned index=T.Touch.PollFrameCount;assert(index<4*T.Touch.Poll.Limit);G96_WIRE_RESULT*f=&T.Touch.PollFrames[index%G96_POLL_WIRES];*f=*from;T.Touch.PollFrameCount=index+1;T.Touch.Poll.Cycles=cycle;
 assert(G96PollPlan(&T.Touch,start,index));unsigned old=f->Payload;f->Payload^=1;unsigned before=Writes;assert(!G96PowerWrite(c,0xa90600,0x18000000)&&Writes==before);f->Payload=old;Cases++;
 if(index>start){
  G96_WIRE_RESULT*p=&T.Touch.PollFrames[(index-1)%G96_POLL_WIRES];uint32_t*fields[]={&p->TransportOk,&p->TxDone,&p->RxDone,&p->State,&p->CancelSent,&p->AbortSent};
  for(unsigned n=0;n<6;n++){old=*fields[n];*fields[n]^=1;assert(!G96PollPlan(&T.Touch,start,index));*fields[n]=old;Cases++;}
  p->Tx[0]^=1;assert(!G96PollPlan(&T.Touch,start,index));p->Tx[0]^=1;Cases++;
 }
 unsigned bytes=f->Kind==G96_WIRE_CLEAR?6:f->Payload+8,command=f->Kind==G96_WIRE_CLEAR?0x08000000u:0x18000000u;
 if(f->Kind==G96_WIRE_CLEAR){old=c->ClearUsed;c->ClearUsed=1+T.Touch.Poll.Limit;before=Writes;assert(!G96PowerWrite(c,0xa90600,command)&&Writes==before);c->ClearUsed=old;Cases++;}
 assert(G96PowerWrite(c,0xa9026c,bytes));if(f->Kind!=G96_WIRE_CLEAR)assert(G96PowerWrite(c,0xa90270,bytes));
 before=Writes;assert(!G96PowerWrite(c,0xa90600,command^0x10000000u)&&Writes==before);Cases++;
 assert(G96PowerWrite(c,0xa90600,command));Send(c,f);Cases++;
}
static void Finish(G96_PWR_CONTEXT*c,unsigned start){
 unsigned end=T.Touch.PollFrameCount,completed=c->CompletedCycles,before;
 assert(G96CycleComplete(&T.Touch,start,end));
 // A next descriptor cannot bypass the independent native checkpoint.
 G96_WIRE_RESULT*next=&T.Touch.PollFrames[end%G96_POLL_WIRES];G96_WIRE_RESULT keep=*next;memset(next,0,sizeof(*next));next->Kind=1;next->Address=0x10274;next->Payload=26;T.Touch.PollFrameCount=end+1;T.Touch.Poll.Cycles++;
 before=Writes;assert(!G96PowerWrite(c,0xa90600,0x18000000)&&Writes==before);Cases++;*next=keep;T.Touch.PollFrameCount=end;T.Touch.Poll.Cycles--;
 unsigned count=T.Touch.PollFrameCount;T.Touch.PollFrameCount=0;before=Writes;assert(!G96PowerWrite(c,0xa90600,0x18000000)&&Writes==before);Cases++;T.Touch.PollFrameCount=count;
 // Every observed busy/quiescence status denies advancement without mutation.
 const unsigned indexes[12][2]={{14,0x40/4},{14,0x800/4},{14,0x804/4},{14,0xe18/4},{14,0xe1c/4},{1,0x130/4},{1,0x230/4},{1,0x330/4},{1,0xc60/4},{14,0x610/4},{14,0x614/4},{14,0x640/4}};
 const uint32_t bad[12]={1,1,1,1,1,0x20,0x20,0x20,0x400,1,0,1};
 for(unsigned i=0;i<12;i++){uint32_t*p=&Memory[indexes[i][0]][indexes[i][1]],old=*p;*p=bad[i];before=Writes;assert(!G96Advance(c)&&c->CycleBase==start&&c->CompletedCycles==completed&&Writes==before);*p=old;Cases++;}
 Present=0;before=Reads;assert(!G96Advance(c)&&Reads==before&&c->CycleBase==start&&c->CompletedCycles==completed);Present=1;Cases++;
 unsigned fifo=c->FifoWords;c->FifoWords^=1;assert(!G96Advance(c)&&c->CycleBase==start&&c->CompletedCycles==completed);c->FifoWords=fifo;Cases++;
 G96_WIRE_RESULT*last=&T.Touch.PollFrames[(end-1)%G96_POLL_WIRES];unsigned was=last->TransportOk;last->TransportOk=0;assert(!G96CycleComplete(&T.Touch,start,end)&&!G96Advance(c));last->TransportOk=was;Cases++;
 before=Reads;assert(G96Advance(c)&&Reads==before+12&&c->CycleBase==end&&c->CompletedCycles==completed+1);Cases++;
 assert(!G96Advance(c)&&c->CycleBase==end&&c->CompletedCycles==completed+1);Cases++;CyclesTested++;
}
int main(int argc,char**argv){assert(argc>=3);G96_PWR_CONTEXT c;unsigned start,cycle;
 for(int variant=1;variant<argc;variant++){
  struct{uint8_t Status[80];G96_TRIAL_RESULT Trial;}saved;FILE*f=fopen(argv[variant],"rb");assert(f&&fread(&saved,1,sizeof(saved),f)==sizeof(saved));fclose(f);Saved=saved.Trial;unsigned wires=Saved.Touch.PollFrameCount;assert(wires<=400);Init(&c,3000);start=cycle=0;
  for(unsigned at=0;at<wires;at++){
   if(Saved.Touch.PollFrames[at].Kind==G96_WIRE_PREFETCH){if(at){Finish(&c,start);start=at;}cycle++;}
   OneWire(&c,&Saved.Touch.PollFrames[at],start,cycle);
  }
  Finish(&c,start);assert(c.CompletedCycles==cycle&&c.CommandUsed==4+wires&&c.ClearUsed<=1+cycle);
 }
 // Repeat one complete modeled 10-contact/retry cycle across all ring boundaries.
 assert(Saved.Touch.PollFrames[0].Kind==1&&Saved.Touch.PollFrames[1].Kind==4&&Saved.Touch.PollFrames[2].Kind==2&&Saved.Touch.PollFrames[3].Kind==3);
 Init(&c,3000);
 for(unsigned epoch=1;epoch<=3000;epoch++){start=T.Touch.PollFrameCount;for(unsigned i=0;i<4;i++)OneWire(&c,&Saved.Touch.PollFrames[i],start,epoch);Finish(&c,start);}
 assert(c.CompletedCycles==3000&&c.CommandUsed==12004&&c.ClearUsed==3001&&T.Touch.PollFrameCount==12000);
 unsigned before=Writes;assert(!G96PowerWrite(&c,0xa90600,0x18000000)&&Writes==before);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"cycles\":%u,\"modeled_3000_cycles_12004_commands_no_global_reset\":true,\"ring_wrap_and_raw_terminal_authority\":true,\"native_separate_checkpoint_fresh12_read_quiescence\":true,\"no_CMD_clear_replay_or_skipped_advance\":true}\n",Cases,CyclesTested);return 0;
}
