/* Actual parser and range guard; callbacks/stack placement are test inputs. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "OpenScmErrorCapture.h"
#include "original-log-fixtures.h"
typedef struct {unsigned char Before[16],Message[512],Anchor,After[16];} BOX;
static BOX Box;
static OL_STATE State;
static unsigned Cases;
static const char Good[]="tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  \r\n";
static void Reset(void){memset(&Box,0,sizeof(Box));OpenScmLogInit(&State);assert(sizeof(State.Report)==272&&State.Report.Size==272&&State.Report.Magic==OL_MAGIC);State.Report.Active=1;}
static void Begin(void){assert(OpenScmLogBegin(&State,0x42000202,36,1,(OL_U64)(uintptr_t)&Box.Anchor));}
static void Put(const char *s){assert(strlen(s)<=sizeof(Box.Message));memcpy(Box.Message,s,strlen(s));}
static OL_U64 Consume(size_t n){return OpenScmLogConsume(&State,Box.Message,n);}
int main(int argc,char **argv){assert(argc==1||argc==2);
 Reset();Begin();Put(Good);assert(Consume(strlen(Good))==strlen(Good)&&State.Report.Count==1&&State.Report.Matched==1);
 OpenScmLogEnd(&State,0x8000000000000007ULL,0xdead);assert(!State.Report.PendingCommand&&State.Report.Records[0].RawStatus==0xfffffffe&&State.Report.Records[0].Command==0x42000202&&State.Report.Records[0].Sequence==1&&State.Report.Records[0].ApiStatus==0x8000000000000007ULL&&State.Report.Records[0].ApiResult0==0xdead);Cases++;
 for(size_t i=0;i<sizeof(OriginalLogFixtures)/sizeof(OriginalLogFixtures[0]);i++){
  const ORIGINAL_LOG *f=&OriginalLogFixtures[i];Reset();assert(OpenScmLogBegin(&State,f->Command,36,f->Command==0x42000201?0:1,(OL_U64)(uintptr_t)&Box.Anchor));memcpy(Box.Message,f->Text,f->Bytes);
  assert(Consume(f->Bytes)==f->Bytes&&State.Report.Count==1&&State.Report.Records[0].RawStatus==f->Raw);
  OpenScmLogEnd(&State,f->ApiStatus,f->Result0);assert(State.Report.Records[0].ApiStatus==f->ApiStatus&&State.Report.Records[0].ApiResult0==f->Result0);Cases++;
 }
 for(size_t n=0;n<strlen(Good);n++){Reset();Begin();Put(Good);Consume(n);assert(!State.Report.Count);Cases++;}
 const char *bad[]={
  "tz_armv8_smc_call failed, TzStatus = 0x,  SmcId = 0x42000202  \r\n",
  "tz_armv8_smc_call failed, TzStatus = 0x1FFFFFFFF,  SmcId = 0x42000202  \r\n",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE, SmcId = 0x42000202  \r\n",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x  \r\n",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x142000202  \r\n",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  ",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  \r\nx",
  "tz_armv8_smc_call failed, TzStatus = 0xFFFFFFFE,  SmcId = 0x42000202  \r\r\r\r\n"};
 for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++){Reset();Begin();Put(bad[i]);Consume(strlen(bad[i]));assert(!State.Report.Count&&(State.Report.ParserFault&OL_BAD_FORMAT));Cases++;}
 Reset();Begin();Put("ordinary debug text\r\n");Consume(21);assert(State.Report.Ignored==1&&!State.Report.Count&&!State.Report.ParserFault);Cases++;
 Reset();Begin();Put("tz_armv8_smc_call failed, TzStatus = 0x1,  SmcId = 0x42000201  \r\n");Consume(strlen((char *)Box.Message));assert(!State.Report.Count&&(State.Report.ParserFault&OL_WRONG_COMMAND));Cases++;
 for(unsigned i=0;i<3;i++){
  Reset();Begin();const void *badptr=(void *)(uintptr_t)(i==0?0xc7b7000ULL:i==1?0xc7b7008ULL:0xb000000ULL);
  assert(!OpenScmLogConsume(&State,badptr,72)&&!State.Report.Count&&(State.Report.ParserFault&OL_BAD_STACK));Cases++;
 }
 Reset();Begin();assert(!OpenScmLogConsume(&State,NULL,72)&&(State.Report.ParserFault&OL_BAD_LENGTH));Cases++;
 Reset();Begin();assert(!Consume(513)&&(State.Report.ParserFault&OL_BAD_LENGTH));Cases++;
 Reset();Begin();State.Report.StackHigh=(OL_U64)(uintptr_t)Box.Message+10;assert(!Consume(11)&&(State.Report.ParserFault&OL_BAD_STACK));Cases++;
 Reset();State.Report.Active=0;assert(!OpenScmLogBegin(&State,0x42000202,36,1,(OL_U64)(uintptr_t)&Box.Anchor));assert(!OpenScmLogConsume(&State,(void *)(uintptr_t)0xc7b7000,72)&&!State.Report.Count);Cases++;
 Reset();assert(!OpenScmLogConsume(&State,(void *)(uintptr_t)0xc7b7000,72)&&!State.Report.Count);Cases++;
 Reset();assert(!OpenScmLogBegin(&State,0x42000205,36,2,(OL_U64)(uintptr_t)&Box.Anchor)&&!State.Report.PendingCommand);Cases++;
 Reset();assert(!OpenScmLogBegin(&State,0x42000202,1,1,(OL_U64)(uintptr_t)&Box.Anchor)&&!State.Report.PendingCommand);Cases++;
 Reset();assert(!OpenScmLogBegin(&State,0x42000202,36,16,(OL_U64)(uintptr_t)&Box.Anchor)&&(State.Report.ParserFault&OL_BAD_STATE));Cases++;
 for(unsigned i=0;i<2;i++){Reset();assert(!OpenScmLogBegin(&State,0x42000202,36,1,i?~0ULL:0)&&(State.Report.ParserFault&OL_BAD_STACK));Cases++;}
 for(unsigned i=0;i<3;i++){Reset();const OL_U64 anchor[]={0x80003fffULL,0xc7b8000ULL,0xb000100ULL};assert(!OpenScmLogBegin(&State,0x42000202,36,1,anchor[i])&&(State.Report.ParserFault&OL_BAD_STACK));Cases++;}
 Reset();Begin();assert(!OpenScmLogBegin(&State,0x42000201,36,0,(OL_U64)(uintptr_t)&Box.Anchor)&&State.Report.PendingCommand==0x42000202);Put(Good);Consume(strlen(Good));assert(State.Report.Count==1);Cases++;
 Reset();Begin();Put(Good);Consume(strlen(Good));Consume(strlen(Good));assert(State.Report.Count==1&&(State.Report.ParserFault&OL_DUPLICATE));OpenScmLogEnd(&State,7,8);assert(State.Report.Records[0].ApiStatus==7);Cases++;
 Reset();State.Report.Count=OL_RECORDS;Begin();Put(Good);Consume(strlen(Good));assert(State.Report.Count==OL_RECORDS&&(State.Report.ParserFault&OL_CAPACITY));Cases++;
 Reset();Begin();State.Report.SinkCalls=State.Report.Rejected=0xffffffffu;Consume(0);assert(State.Report.SinkCalls==0xffffffffu&&State.Report.Rejected==0xffffffffu);Cases++;
 Reset();Begin();Put("tz_armv8_smc_call failed, TzStatus = 0xfffffffe,  SmcId = 0x42000202  \r\r\n");Consume(strlen((char *)Box.Message));assert(State.Report.Count==1&&State.Report.Records[0].RawStatus==0xfffffffe);Cases++;
 Reset();Begin();Put(Good);Consume(strlen(Good));OpenScmLogEnd(&State,0x8000000000000007ULL,0);
 State.Report.Active=0;State.Report.ImageBase=0x51000000;State.Report.CacheSlot=0x5100e580;State.Report.Proxy=0x60000000;State.Report.OriginalMethod=0x51003f94;State.Report.HookStatus=State.Report.RestoreStatus=0;State.Report.HookStores=2;
 if(argc==2){FILE *f=fopen(argv[1],"wb");assert(f&&fwrite(&State.Report,1,sizeof(State.Report),f)==sizeof(State.Report)&&!fclose(f));}
 printf("{\"passed\":true,\"cases\":%u,\"actual_original_formatter_fixtures\":%zu,\"actual_capture_C\":true,\"ASan_UBSan\":true,\"native_operations\":0}\n",Cases,sizeof(OriginalLogFixtures)/sizeof(OriginalLogFixtures[0]));return 0;
}
