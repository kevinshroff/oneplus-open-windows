/* G201 fixed cover clear plus observers. Existing G182/G195/G200 unchanged. */
#include "g201_handoff.h"
#include "g201_plan.h"
#include "g201_binding.h"

#ifdef G201_HOST
#include <string.h>
#define CopyMem memcpy
#define ZeroMem(p,n) memset((p),0,(n))
#define STATIC static
#define CONST const
#define VOID void
#else
#include <Library/BaseMemoryLib.h>
#endif
#include "OpenSha256.h"

static UINT32 U32(const UINT8 *p)
{ return (UINT32)p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24); }
static UINT64 U64(const UINT8 *p) { return U32(p)|((UINT64)U32(p+4)<<32); }
static int Same(const UINT8 *a,const UINT8 *b,UINTN n)
{ for(UINTN i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1; }
static int Extent(UINT64 a,UINT64 n) { return n&&n<=~(UINT64)0-a; }
static int Overlap(UINT64 a,UINT64 n,UINT64 b,UINT64 m)
{ return a<b+m&&b<a+n; }
int G201PixelCachePlan(UINT32 line,UINT64 *start,UINT64 *end,UINT32 *lines)
{
 const UINT64 a=G201_FB_PAGE+G201_FB_OFFSET,b=a+G201_FB_BYTES;
 if(line<16||line>4096||(line&(line-1))||(a&(line-1))||(b&(line-1)))return 0;
 *start=a;*end=b;*lines=G201_FB_BYTES/line;return 1;
}
static const UINT64 Targets[G201_TARGETS][2]={
 {G201_FB_PAGE,G201_FB_MAP_BYTES},{0xaf08000,4096},{0xaf09000,4096},
 {0xae05000,4096},{0xae07000,4096},{0xae09000,4096},{0xae0b000,4096}
};
static const UINT8 *Desc(const G201_ENV *r,UINTN i)
{ return r->Map+i*r->DescriptorBytes; }
static int Descriptor(const UINT8 *d,UINT64 *a,UINT64 *n)
{
 UINT64 pages=U64(d+24);*a=U64(d+8);
 if(!pages||pages>(~(UINT64)0>>12)||(*a&4095))return 0;
 *n=pages<<12;return Extent(*a,*n);
}
static int Covered(const G201_ENV *r,UINT64 at,UINT64 bytes,int type)
{
 UINT64 end=at+bytes,cursor=at;
 while(cursor<end){
  UINT64 next=cursor;
  for(UINTN i=0;i<r->MapBytes/r->DescriptorBytes;i++){
   const UINT8 *d=Desc(r,i);UINT64 a,n;UINT32 t=U32(d);
   if(!Descriptor(d,&a,&n))return 0;
   /* ACPI pointers may refer only to populated firmware allocations, never
    * conventional/unaccepted/unusable RAM, reserved holes or MMIO. */
   int allowed=type<0?(t==1||t==2||t==3||t==4||t==5||t==6||t==9||t==10):t==(UINT32)type;
   if(allowed&&!(U64(d+32)&0x2000ULL)&&a<=cursor&&cursor<a+n)next=a+n;
  }
  if(next==cursor)return 0;cursor=next;
 }
 return 1;
}
int G201ValidateMap(const G201_ENV *r)
{
 if(!r||r->MapBytes==0||r->MapBytes>G201_MAP_CAPACITY||r->DescriptorBytes<40||
    r->DescriptorBytes>256||(r->DescriptorBytes&7)||r->MapBytes%r->DescriptorBytes||
    r->MapBytes/r->DescriptorBytes>G201_MAX_DESCRIPTORS||r->DescriptorVersion!=1)return G201_BAD_MAP;
 UINTN count=r->MapBytes/r->DescriptorBytes;
 for(UINTN i=0;i<count;i++){
  UINT64 a,n;if(!Descriptor(Desc(r,i),&a,&n)||U32(Desc(r,i))>15)return G201_BAD_MAP;
  for(UINTN j=0;j<i;j++){UINT64 b,m;if(!Descriptor(Desc(r,j),&b,&m)||Overlap(a,n,b,m))return G201_BAD_MAP;}
  for(UINTN t=0;t<G201_TARGETS;t++)if(Overlap(a,n,Targets[t][0],Targets[t][1])){
   UINT32 type=U32(Desc(r,i));
   if(t?(type!=0u&&type!=11u):type!=0u)return G201_TARGET_IS_MANAGED;
   if(U64(Desc(r,i)+32)&(t?0x2000ULL:0x23000ULL))return G201_BAD_CACHE;
  }
 }
 for(UINTN t=0;t<G201_TARGETS;t++){
  /* GetMemoryMap includes all RAM but may omit non-runtime MMIO. Positive
   * MMIO evidence comes from mandatory full-span current GCD MMIO/UC below;
   * every returned UEFI descriptor was still checked for managed overlap. */
  if(!t&&!Covered(r,Targets[t][0],Targets[t][1],0))return G201_TARGET_IS_MANAGED;
  const G201_GCD *g=&r->Gcd[t];
  UINT64 cache=g->Attributes&0x1fULL;
  if(!g->Valid||!Extent(g->Base,g->Bytes)||g->Base>Targets[t][0]||
      g->Base+g->Bytes<Targets[t][0]+Targets[t][1]||g->Kind!=(t?3u:1u)||
      (g->Attributes&(t?0x2000ULL:0x23000ULL))||(t?cache!=1u:(cache!=4u&&cache!=8u)))return G201_BAD_CACHE;
 }
 return G201_READ_COMPLETE;
}
int G201RamCovered(const G201_ENV *r,UINT64 at,UINT64 bytes)
{ return Extent(at,bytes)&&Covered(r,at,bytes,-1); }

static int Ram(const G201_ENV *r,const G201_IO *io,UINT64 at,void *out,UINTN n)
{ return G201RamCovered(r,at,n)&&io->ReadRam(io->Context,at,out,n); }
static int Checksum(const UINT8 *b,UINTN n)
{ UINT8 sum=0;for(UINTN i=0;i<n;i++)sum=(UINT8)(sum+b[i]);return sum==0; }
static int Table(const G201_ENV *r,const G201_IO *io,UINT64 at,UINT8 b[4096],UINT32 *n)
{
 if(!Ram(r,io,at,b,36))return 0;*n=U32(b+4);
 return *n>=36&&*n<=4096&&Ram(r,io,at,b,*n)&&Checksum(b,*n);
}
static int Acpi(const G201_ENV *r,const G201_IO *io)
{
 UINT8 rsdp[36],xsdt[4096],table[4096];UINT32 n=0,xn=0,dsdt=0,ssdt=0,fadt=0;
 if(!Ram(r,io,r->Rsdp,rsdp,36)||!Same(rsdp,(const UINT8 *)"RSD PTR ",8)||
    rsdp[15]<2||U32(rsdp+20)!=36||!Checksum(rsdp,20)||!Checksum(rsdp,36)||
    !Table(r,io,U64(rsdp+24),xsdt,&xn)||!Same(xsdt,(const UINT8 *)"XSDT",4)||
    (xn-36)%8||(xn-36)/8>128)return 0;
 for(UINTN i=36;i<xn;i+=8){
  UINT64 at=U64(xsdt+i);
  /* Only child headers are read initially; irrelevant large CSRT remains untouched. */
  if(!Ram(r,io,at,table,36))return 0;
  if(Same(table,(const UINT8 *)"SSDT",4)&&Same(table+16,(const UINT8 *)"OPRES182",8)){
   if(!Table(r,io,at,table,&n)||n!=sizeof(G201ExpectedSsdt)||!Same(table,G201ExpectedSsdt,n))return 0;
   ssdt++;
  }
  if(Same(table,(const UINT8 *)"FACP",4)){
   if(++fadt!=1||!Table(r,io,at,table,&n)||n<148)return 0;
   UINT64 address=U64(table+140);if(!address)address=U32(table+40);
   if(!Table(r,io,address,table,&n)||n!=sizeof(G201ExpectedDsdt)||!Same(table,G201ExpectedDsdt,n))return 0;
   dsdt++;
  }
 }
 return dsdt==1&&ssdt==1&&fadt==1;
}
static int Gates(const G201_IO *io,UINT32 *snapshot)
{
 UINT32 a[3],b[2];
 if(!io->ReadRegister(io->Context,0xaf08000,&a[0])||!io->ReadRegister(io->Context,0xaf0800c,&a[1])||
    !io->ReadRegister(io->Context,0xaf080a4,&a[2])||!io->ReadRegister(io->Context,0xaf09000,&b[0])||
    !io->ReadRegister(io->Context,0xaf09004,&b[1]))return 0;
 if(snapshot){for(UINTN i=0;i<3;i++)snapshot[i]=a[i];for(UINTN i=0;i<2;i++)snapshot[i+3]=b[i];}
 return G201Gate(a,b);
}
static int Pipeline(const G201_IO *io,G201_SNAPSHOT *s,UINTN stage)
{
 if(!Gates(io,s->Gates[stage]))return G201_GATE_FAILED;
 for(UINTN i=0;i<4;i++)for(UINTN j=0;j<12;j++){
  if(!Gates(io,0))return G201_GATE_FAILED;
  if(!io->ReadRegister(io->Context,G201PipePages[i]+G201Off[j],&s->Pipe[stage][i][j])||
     s->Pipe[stage][i][j]!=G201Expected[i][j])return G201_PIPE_FAILED;
 }
 return Gates(io,0)?G201_READ_COMPLETE:G201_GATE_FAILED;
}
void G201Observe(const G201_ENV *r,const G201_IO *io,G201_SNAPSHOT *s,int fresh,int refresh_cache)
{
 ZeroMem(s,sizeof(*s));s->MapFresh=fresh?1:0;
 if(!r||!io||!io->ReadRam||!io->ReadRegister||!io->ReadRow){s->Status=G201_SERVICE_FAILED;return;}
 if(!r->SourceProfile||!r->CpuArchPresent){s->Status=G201_SOURCE_PROFILE_FAILED;return;}
 s->Status=(UINT32)G201ValidateMap(r);if(s->Status!=G201_READ_COMPLETE)return;
 s->MapCount=r->MapBytes/r->DescriptorBytes;
 if(!Acpi(r,io)){s->Status=G201_BAD_ACPI;return;}s->AcpiMatched=1;
 s->Status=(UINT32)Pipeline(io,s,0);if(s->Status!=G201_READ_COMPLETE)return;
 if(refresh_cache){
  if(!io->SyncPixels||!io->SyncPixels(io->Context)){s->Status=G201_CACHE_SYNC_FAILED;return;}
  s->CacheRefreshed=1;
 }
 OPEN_SHA256 sha;UINT32 row[G201_WIDTH];OpenShaInit(&sha);
 for(UINT32 y=0;y<G201_HEIGHT;y++){
  if(!Gates(io,0)){s->Status=G201_GATE_FAILED;return;}
  if(!io->ReadRow(io->Context,y,row)){s->Status=G201_READ_FAILED;return;}
  for(UINTN x=0;x<G201_WIDTH;x++)if(row[x])s->NonzeroWords++;
  OpenShaUpdate(&sha,row,sizeof(row));s->CompleteWords+=G201_WIDTH;
 }
 OpenShaFinal(&sha,s->PixelSha256);
 s->Status=(UINT32)Pipeline(io,s,1);
}

static int ClearPipeline(const G201_IO *io,G201_CLEAR *s,UINTN stage)
{
 if(!Gates(io,s->Gates[stage]))return G201_GATE_FAILED;
 for(UINTN i=0;i<4;i++)for(UINTN j=0;j<12;j++){
  if(!Gates(io,0))return G201_GATE_FAILED;
  if(!io->ReadRegister(io->Context,G201PipePages[i]+G201Off[j],&s->Pipe[stage][i][j])||
     s->Pipe[stage][i][j]!=G201Expected[i][j])return G201_PIPE_FAILED;
 }
 return Gates(io,0)?G201_READ_COMPLETE:G201_GATE_FAILED;
}
void G201ClearOnce(const G201_ENV *r,const G201_IO *io,const G201_SNAPSHOT *prior,G201_CLEAR *s)
{
 /* Terminal on every outcome, including refusal or a partial clear. No retry. */
 if(s->Status!=G201_NOT_RUN||s->Attempted)return;
 if(!r||!io||!prior||!io->ReadRam||!io->ReadRegister||!io->ReadRow||!io->WriteZeroRow||!io->SyncPixels){s->Status=G201_SERVICE_FAILED;return;}
 if(prior->Status!=G201_READ_COMPLETE||prior->CompleteWords!=G201_WORDS||!prior->MapFresh||!prior->AcpiMatched||!prior->CacheRefreshed){s->Status=G201_PRIOR_STAGE_FAILED;return;}
 s->PriorReadAccepted=1;
 if(!r->SourceProfile||!r->CpuArchPresent){s->Status=G201_SOURCE_PROFILE_FAILED;return;}
 s->Status=(UINT32)G201ValidateMap(r);if(s->Status!=G201_READ_COMPLETE)return;
 if(!Acpi(r,io)){s->Status=G201_BAD_ACPI;return;}
 s->Status=(UINT32)ClearPipeline(io,s,0);if(s->Status!=G201_READ_COMPLETE)return;
 s->Attempted=1;
 for(UINT32 y=0;y<G201_HEIGHT;y++){
  if(!Gates(io,0)){s->Status=G201_GATE_FAILED;goto sync_partial;}
  UINT32 before=s->WrittenWords;
  if(!io->WriteZeroRow(io->Context,y,&s->WrittenWords)||s->WrittenWords!=before+G201_WIDTH){s->Status=G201_WRITE_FAILED;goto sync_partial;}
 }
 if(!io->SyncPixels(io->Context)){s->Status=G201_CACHE_SYNC_FAILED;return;}s->CacheSynced=1;
 s->Status=(UINT32)ClearPipeline(io,s,1);if(s->Status!=G201_READ_COMPLETE)return;
 OPEN_SHA256 sha;UINT32 row[G201_WIDTH];OpenShaInit(&sha);
 for(UINT32 y=0;y<G201_HEIGHT;y++){
  if(!Gates(io,0)){s->Status=G201_GATE_FAILED;return;}
  if(!io->ReadRow(io->Context,y,row)){s->Status=G201_READ_FAILED;return;}
  for(UINTN x=0;x<G201_WIDTH;x++)if(row[x])s->NonzeroWords++;
  OpenShaUpdate(&sha,row,sizeof(row));s->VerifiedWords+=G201_WIDTH;
 }
 OpenShaFinal(&sha,s->ReadbackSha256);
 s->Status=(UINT32)ClearPipeline(io,s,2);if(s->Status!=G201_READ_COMPLETE)return;
 if(s->NonzeroWords)s->Status=G201_VERIFY_FAILED;
 return;
 sync_partial:
 /* Make even a partial WT store pass visible before retaining its failure.
  * Cache operations touch fixed pixel cache lines, never display registers. */
 if(s->WrittenWords){if(io->SyncPixels(io->Context))s->CacheSynced=1;else s->Status=G201_CACHE_SYNC_FAILED;}
}
