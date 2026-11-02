/* SPDX-License-Identifier: MIT -- G530 stock-lease/on-state ID-only profile.
 * Reuses G417 exact LoadedImage/text binding, extends only with bounded pool
 * client reads and public IsOn/IsEnabled queries. Actual Enable is called by
 * G290GpuPower.c between G530Before/After. No MMIO/control writes here.
 */
#include <Uefi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/EFIClock.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include "OpenSha256.h"
#include "G530Lease.h"
STATIC_ASSERT(OFFSET_OF(EFI_CLOCK_PROTOCOL,IsClockOn)==40,"Clock IsOn ABI");
#include "ClockPins.h"
#include "G417LoadedBase.h"
#pragma pack(push,1)
typedef struct {
 UINT32 Signature,Length;UINT8 Revision,Checksum,OemId[6];
 UINT64 OemTableId;UINT32 OemRevision,CreatorId,CreatorRevision;
} HEADER;
typedef struct {
 HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT64 ProtocolVersion,ImageBase,ImageBytes,ProtocolPa,ClockId;
 UINT32 ReadMask,StableMask,DiffStaticMask,Reserved;
 UINT8 TextSha[32];UINT32 NodeRva,DomainRva,OpsRva,Reserved2;
 UINT8 Node[2][104],Domain[2][104],Ops[2][32];
 UINT32 HeaderFactMask;UINT8 Dos64[64],Pe64[64];
 UINT64 ActiveBspAnchor,StaticClockTableAnchor;UINT32 StaticClockCountAnchor;
} REPORT;
#pragma pack(pop)
STATIC_ASSERT(sizeof(REPORT)==788,"OGDS ABI");
static REPORT mR;
static UINT16 U16(CONST VOID*p){UINT16 v;CopyMem(&v,p,2);return v;}
static UINT32 U32(CONST VOID*p){UINT32 v;CopyMem(&v,p,4);return v;}
static UINT64 U64(CONST VOID*p){UINT64 v;CopyMem(&v,p,8);return v;}
static BOOLEAN In(UINTN base,UINTN bytes,UINTN at,UINTN n)
{return n<=bytes&&at>=base&&at-base<=bytes-n;}
static BOOLEAN Data(UINTN base,UINTN at,UINTN n)
{return In(base+0x1b000,0x15000,at,n);}
static EFI_STATUS Inspect(EFI_CLOCK_PROTOCOL*c)
{
 EFI_HANDLE *h=NULL;UINTN count=0,found=0,base=0,bytes=0;
 EFI_STATUS st;EFI_LOADED_IMAGE_PROTOCOL *li=NULL;
 UINTN get=(UINTN)c->GetClockID;
 mR.Stage=1;mR.ProtocolVersion=c->Version;mR.ProtocolPa=(UINTN)c;
 if(c->Version!=0x1000a||!get) return EFI_UNSUPPORTED;
 /* Enumerate supported LoadedImage metadata only, never scan backwards from
  * an arbitrary code pointer. Bound the inventory and require one owner. */
 st=gBS->LocateHandleBuffer(ByProtocol,&gEfiLoadedImageProtocolGuid,NULL,&count,&h);
 if((st!=EFI_SUCCESS)) return st;
 if(count>256) {FreePool(h);return EFI_UNSUPPORTED;}
 for(UINTN j=0;j<count;j++) {
  st=gBS->HandleProtocol(h[j],&gEfiLoadedImageProtocolGuid,(VOID**)&li);
  if((st!=EFI_SUCCESS)||!li||!li->ImageBase||li->ImageSize>MAX_UINTN) continue;
  if(In((UINTN)li->ImageBase,(UINTN)li->ImageSize,get,4)) {
   found++;base=(UINTN)li->ImageBase;bytes=(UINTN)li->ImageSize;
  }
 }
 FreePool(h);if(found!=1) return EFI_NOT_FOUND;
 mR.ImageBase=base;mR.ImageBytes=bytes;mR.Stage=2;
 if(bytes<CLOCK_IMAGE_BYTES||bytes>0x100000||base>MAX_UINTN-bytes) return EFI_BAD_BUFFER_SIZE;
 CopyMem(mR.Dos64,(VOID*)base,64);mR.HeaderFactMask=1;
 UINTN pe=U32(mR.Dos64+60);
 if(pe<=0x1000u-64u&&In(base,bytes,base+pe,64)) {
  CopyMem(mR.Pe64,(VOID*)(base+pe),64);mR.HeaderFactMask|=2;
 }
 if(get!=base+0x14e4||(UINTN)c->EnableClock!=base+0x1524||
    (UINTN)c->IsClockEnabled!=base+0x15ac||(UINTN)c->IsClockOn!=base+0x15ec) return EFI_UNSUPPORTED;
 /* All header reads remain inside this supported LoadedImage allocation. */
 if(U16((VOID*)base)!=0x5a4d) return EFI_COMPROMISED_DATA;
 if(!G417PeOffsetValid(pe,bytes)||!In(base,bytes,base+pe,0x108)) return EFI_COMPROMISED_DATA;
 UINT8*p=(UINT8*)(base+pe);UINT16 opt=U16(p+20);
 if(U32(p)!=0x4550||U16(p+4)!=0xaa64||U16(p+6)!=3||opt!=0xf0||
    U16(p+24)!=0x20b||!G417LoadedBaseMatches(U64(p+24+24),base)||U32(p+24+56)!=CLOCK_IMAGE_BYTES||
    U16(p+24+68)!=11) return EFI_UNSUPPORTED;
 UINT8*s=p+24+opt;
 if(!In(base,bytes,(UINTN)s,120)||CompareMem(s,".text",5)||
    U32(s+8)!=CLOCK_TEXT_BYTES||U32(s+12)!=CLOCK_TEXT_RVA||
    U32(s+36)!=0x60000020||CompareMem(s+40,".data",5)||
    U32(s+48)!=0x15000||U32(s+52)!=0x1b000||U32(s+76)!=0xc0000040)
  return EFI_UNSUPPORTED;
 mR.Stage=3;
 UINT8*text=AllocatePool(CLOCK_TEXT_BYTES);if(!text)return EFI_OUT_OF_RESOURCES;
 CopyMem(text,(VOID*)(base+CLOCK_TEXT_RVA),CLOCK_TEXT_BYTES);
 /* Undo only the185 pinned DIR64 relocations inside this immutable text.
  * Do not trust or walk the runtime relocation directory/data pointers. */
 for(UINTN i=0;i<sizeof(mTextRelocs)/sizeof(mTextRelocs[0]);i++) {
  UINTN off=mTextRelocs[i];UINT64 v=U64(text+off)-base;CopyMem(text+off,&v,8);
 }
 OpenShaAll(text,CLOCK_TEXT_BYTES,mR.TextSha);FreePool(text);
 if(CompareMem(mR.TextSha,mTextSha,32)) return EFI_SECURITY_VIOLATION;
 mR.Stage=4;
 /* Confirm the fixed node belongs to the CURRENT selected runtime BSP,
  * rather than report a stale image-resident table after a BSP switch.
  * These three fixed slots all lie in the validated .data allocation. */
 mR.ActiveBspAnchor=U64((VOID*)(base+0x2ee40));
 mR.StaticClockTableAnchor=U64((VOID*)(base+0x25b20));
 mR.StaticClockCountAnchor=U32((VOID*)(base+0x25b28));mR.ReadMask|=8;
 if(mR.ActiveBspAnchor!=base+0x25b00||
    mR.StaticClockTableAnchor!=base+0x1b360||
    mR.StaticClockCountAnchor!=0x15d)return EFI_UNSUPPORTED;
 mR.Reserved=0x1b360;mR.Reserved2=0x25b00;
 UINTN id=MAX_UINTN;
 st=c->GetClockID(c,"gpu_cc_ahb_clk",&id);mR.ClockId=id;
 if((st!=EFI_SUCCESS))return st;if(id!=0x1014a)return EFI_UNSUPPORTED;
 /* Exact lookup identity anchors this fixed node. No index from arbitrary
  * runtime input. This binding phase stays image-only; the separate bounded
  * pool extension below validates each client-node span before reading it. */
 mR.NodeRva=0x23970;UINTN node=base+mR.NodeRva;
 if(!Data(base,node,104))return EFI_COMPROMISED_DATA;
 mR.Stage=5;
 for(UINTN n=0;n<2;n++){MemoryFence();CopyMem(mR.Node[n],(VOID*)node,104);MemoryFence();}
 mR.ReadMask|=1;
 if(CompareMem(mR.Node[0],mR.Node[1],104))return EFI_NOT_READY;mR.StableMask|=1;
 UINTN name=(UINTN)U64(mR.Node[0]),dom=(UINTN)U64(mR.Node[0]+8);
 UINTN ops=(UINTN)U64(mR.Node[0]+0x38);
 if(!In(base+0x1000,0x1a000,name,15)||CompareMem((VOID*)name,"gpu_cc_ahb_clk",15)||
    !Data(base,dom,104)||!Data(base,ops,32))return EFI_COMPROMISED_DATA;
 mR.DomainRva=(UINT32)(dom-base);mR.OpsRva=(UINT32)(ops-base);
 mR.Stage=6;
 for(UINTN n=0;n<2;n++) {
  MemoryFence();CopyMem(mR.Domain[n],(VOID*)dom,104);
  CopyMem(mR.Ops[n],(VOID*)ops,32);MemoryFence();
 }
 mR.ReadMask|=6;
 if(CompareMem(mR.Domain[0],mR.Domain[1],104)||CompareMem(mR.Ops[0],mR.Ops[1],32))return EFI_NOT_READY;
 mR.StableMask|=6;
 /* Never dereference CBCR/reset/voter addresses: report the numbers only.
  * Each captured HAL target must point into the hash-pinned executable text. */
 for(UINTN j=0;j<4;j++)if(!In(base+0x1000,0x1a000,(UINTN)U64(mR.Ops[0]+8*j),4))return EFI_COMPROMISED_DATA;
 if(U64(mR.Node[0]+0x18)!=0x03d9911c)mR.DiffStaticMask|=1;
 if(U64(mR.Node[0]+0x20)!=0x03d99104)mR.DiffStaticMask|=2;
 if(U64(mR.Node[0]+0x28)||U32(mR.Node[0]+0x30))mR.DiffStaticMask|=4;
 if(dom!=base+0x29fa8)mR.DiffStaticMask|=8;
 if(ops!=base+0x2ec00)mR.DiffStaticMask|=16;
 CONST UINT32 expected[4]={0xe1dc,0xe208,0xe238,0xe270};
 for(UINTN j=0;j<4;j++)if(U64(mR.Ops[0]+8*j)!=base+expected[j])mR.DiffStaticMask|=32;
 mR.Stage=7;return EFI_SUCCESS;
}

/* Exact GetID1e0c allocates/zeros24B: next+0, owner+8, refs+10/+12.
 * Unlike G417, this scoped extension follows at most16 existing pool nodes,
 * only after a fresh BootServicesData memory-map span check for each24B. */
STATIC_ASSERT(sizeof(G530_REF)==80,"G530 ref ABI");
STATIC_ASSERT(sizeof(G530_REPORT)==316,"OGSL ABI");
static G530_REPORT mLease;
static union {UINT64 Align;UINT8 Bytes[32768];} mMapStorage;
#define mMap mMapStorage.Bytes
static UINTN mMapBytes,mDescBytes;
static EFI_CLOCK_PROTOCOL *mClock;
static EFI_STATUS MemoryMap(VOID)
{
 UINTN key=0;UINT32 version=0;mMapBytes=sizeof(mMap);mDescBytes=0;
 EFI_STATUS st=gBS->GetMemoryMap(&mMapBytes,(EFI_MEMORY_DESCRIPTOR*)mMap,&key,&mDescBytes,&version);
 if(st!=EFI_SUCCESS)return st;
 if(version!=EFI_MEMORY_DESCRIPTOR_VERSION||mDescBytes<sizeof(EFI_MEMORY_DESCRIPTOR)||
    mMapBytes>sizeof(mMap)||mMapBytes%mDescBytes||mMapBytes/mDescBytes>512)return EFI_UNSUPPORTED;
 return EFI_SUCCESS;
}
static BOOLEAN Pool(UINTN at)
{
 if(!at||(at&7)||at>MAX_UINTN-24)return FALSE;
 for(UINTN off=0;off<mMapBytes;off+=mDescBytes) {
  EFI_MEMORY_DESCRIPTOR d;CopyMem(&d,mMap+off,sizeof(d));
  if(d.Type!=EfiBootServicesData||(d.Attribute&EFI_MEMORY_RP)||
     d.NumberOfPages>MAX_UINT64/4096)continue;
  UINT64 n=d.NumberOfPages*4096;
  if(d.PhysicalStart>MAX_UINT64-n)continue;
  if(n>=24&&at>=d.PhysicalStart&&at-d.PhysicalStart<=n-24)return TRUE;
 }
 return FALSE;
}
static EFI_STATUS Capture(G530_REF*r,UINT32*visited)
{
 UINTN b=(UINTN)mLease.ImageBase;UINTN seen[16];UINT8 raw[24];
 ZeroMem(r,sizeof(*r));*visited=0;
 if(!mClock||mClock->Version!=0x1000a||(UINTN)mClock->EnableClock!=b+0x1524||
    (UINTN)mClock->IsClockEnabled!=b+0x15ac||(UINTN)mClock->IsClockOn!=b+0x15ec)
  return EFI_UNSUPPORTED;
 r->Bsp=U64((VOID*)(b+0x2ee40));r->DalClient=U64((VOID*)(b+0x2ee38));
 if(r->Bsp!=b+0x25b00||!r->DalClient||U64((VOID*)(b+0x25b20))!=b+0x1b360||
    U32((VOID*)(b+0x25b28))!=0x15d)return EFI_UNSUPPORTED;
 r->Bypass=*(volatile UINT8*)(b+0x25b6d);
 UINTN node=b+0x23970,dom=b+0x29fa8,ops=b+0x2ec00;
 r->NodeFlags=U32((VOID*)(node+0x10));r->DomainFlags=U32((VOID*)(dom+0x18));
 if((r->Bypass&8)||r->NodeFlags||r->DomainFlags||
    U64((VOID*)(node+8))!=dom||U64((VOID*)(node+0x18))!=0x03d9911c||
    U64((VOID*)(node+0x28))||U32((VOID*)(node+0x30))||U64((VOID*)(node+0x38))!=ops||
    U64((VOID*)ops)!=b+0xe1dc||U64((VOID*)(ops+0x10))!=b+0xe238||
    U64((VOID*)(ops+0x18))!=b+0xe270)return EFI_UNSUPPORTED;
 r->NodeRef=U16((VOID*)(node+0x48));r->NodeSupp=U16((VOID*)(node+0x4a));
 r->DomainRef=U16((VOID*)(dom+0x40));r->DomainSupp=U16((VOID*)(dom+0x42));
 r->Head=U64((VOID*)(node+0x50));UINTN at=(UINTN)r->Head;
 for(UINTN i=0;i<16&&at;i++) {
  for(UINTN j=0;j<i;j++)if(seen[j]==at)return EFI_COMPROMISED_DATA;
  seen[i]=at;if(!Pool(at))return EFI_ACCESS_DENIED;
  MemoryFence();CopyMem(raw,(VOID*)at,24);MemoryFence();*visited=(UINT32)i+1;
  if(U64(raw+8)==r->DalClient) {
   r->RefNode=at;r->Next=U64(raw);r->RefOwner=U64(raw+8);
   r->ClientRef=U16(raw+0x10);r->ClientSupp=U16(raw+0x12);return EFI_SUCCESS;
  }
  at=(UINTN)U64(raw);
 }
 return EFI_NOT_FOUND;
}
static EFI_STATUS Pair(G530_REF*r,UINT32*visited)
{
 G530_REF again;UINT32 n;EFI_STATUS st=MemoryMap();if(st!=EFI_SUCCESS)return st;
 st=Capture(r,visited);if(st!=EFI_SUCCESS)return st;
 st=Capture(&again,&n);if(st!=EFI_SUCCESS)return st;
 if(CompareMem(r,&again,sizeof(again))||n!=*visited)return EFI_NOT_READY;
 return EFI_SUCCESS;
}
VOID G530Init(VOID)
{
 ZeroMem(&mLease,sizeof(mLease));mLease.Header.Signature=SIGNATURE_32('O','G','S','L');
 mLease.Header.Length=sizeof(mLease);mLease.Header.Revision=1;
 CopyMem(mLease.Header.OemId,"OPEN  ",6);mLease.Header.OemTableId=SIGNATURE_64('G','5','3','0','L','E','A','S');
 mLease.Header.OemRevision=1;mLease.Header.CreatorId=SIGNATURE_32('O','P','E','N');
 mLease.Header.CreatorRevision=1;mLease.Version=1;mLease.Status=EFI_NOT_READY;
 mLease.EnableStatus=EFI_NOT_READY;mLease.IsOnStatus=EFI_NOT_READY;mLease.IsEnabledStatus=EFI_NOT_READY;
 mLease.IsOn=MAX_UINT32;mLease.IsEnabled=MAX_UINT32;
}
EFI_STATUS G530Bind(EFI_CLOCK_PROTOCOL*c,UINTN*id)
{
 mLease.Stage=1;EFI_STATUS st=Inspect(c);mLease.BindStage=mR.Stage;
 mLease.ImageBase=mR.ImageBase;CopyMem(mLease.TextSha,mR.TextSha,32);
 if(st!=EFI_SUCCESS||mR.Stage!=7||mR.DiffStaticMask) {if(st==EFI_SUCCESS)st=EFI_UNSUPPORTED;goto done;}
 mClock=c;*id=(UINTN)mR.ClockId;mLease.ClockId=*id;mLease.Stage=2;
 done:mLease.Status=st;return st;
}
EFI_STATUS G530Before(EFI_CLOCK_PROTOCOL*c)
{
 EFI_STATUS st=EFI_NOT_READY;if(c!=mClock||mLease.Stage!=2)goto done;
 st=Pair(&mLease.Ref[0],&mLease.PoolCheckedNodes[0]);if(st!=EFI_SUCCESS)goto done;
 G530_REF*r=&mLease.Ref[0];
 if(r->ClientRef>r->NodeRef||r->ClientSupp>r->NodeSupp||
    r->NodeRef==MAX_UINT16||r->ClientRef==MAX_UINT16||
    (!r->NodeRef&&r->DomainRef==MAX_UINT16)||(r->NodeRef&&!r->DomainRef)) {st=EFI_ACCESS_DENIED;goto done;}
 mLease.Client=r->DalClient;mLease.Stage=3;
 done:mLease.Status=st;return st;
}
EFI_STATUS G530After(EFI_CLOCK_PROTOCOL*c,EFI_STATUS enable)
{
 EFI_STATUS st=enable;mLease.EnableStatus=enable;
 if(enable!=EFI_SUCCESS)goto done;
 if(c!=mClock||mLease.Stage!=3){st=EFI_NOT_READY;goto done;}
 st=Pair(&mLease.Ref[1],&mLease.PoolCheckedNodes[1]);if(st!=EFI_SUCCESS)goto done;
 G530_REF*a=&mLease.Ref[0],*b=&mLease.Ref[1];
 if(a->Bsp!=b->Bsp||a->DalClient!=b->DalClient||a->Head!=b->Head||a->RefNode!=b->RefNode||
    a->Next!=b->Next||a->RefOwner!=b->RefOwner||a->NodeFlags!=b->NodeFlags||
    a->DomainFlags!=b->DomainFlags||a->Bypass!=b->Bypass||
    b->NodeRef!=(UINT16)(a->NodeRef+1)||b->ClientRef!=(UINT16)(a->ClientRef+1)||
    b->NodeSupp!=a->NodeSupp||b->ClientSupp!=a->ClientSupp||b->DomainSupp!=a->DomainSupp||
    b->DomainRef!=(UINT16)(a->DomainRef+(a->NodeRef==0))) {st=EFI_NOT_READY;goto done;}
 mLease.LeaseAccepted=1;mLease.Stage=4;
 done:mLease.Status=st;return st;
}
EFI_STATUS G530On(EFI_CLOCK_PROTOCOL*c,UINT32 raw)
{
 EFI_STATUS st=EFI_NOT_READY;BOOLEAN on=0xa5,enabled=0xa5;
 if(c!=mClock||!mLease.LeaseAccepted||mLease.Status!=EFI_SUCCESS||raw==MAX_UINT32||
    !((raw>>28)==0||(raw>>28)==2))goto done;
 /* Fresh binding/ref state must still equal our accepted post-call record. */
 G530_REF now;UINT32 n;st=Pair(&now,&n);if(st!=EFI_SUCCESS)goto done;
 if(CompareMem(&now,&mLease.Ref[1],sizeof(now))){st=EFI_NOT_READY;goto done;}
 st=c->IsClockOn(c,0x1014a,&on);mLease.IsOnStatus=st;mLease.IsOn=on;
 if(st!=EFI_SUCCESS)goto done;if(on!=TRUE){st=EFI_DEVICE_ERROR;goto done;}
 st=c->IsClockEnabled(c,0x1014a,&enabled);mLease.IsEnabledStatus=st;mLease.IsEnabled=enabled;
 if(st!=EFI_SUCCESS)goto done;
 if(enabled!=FALSE&&enabled!=TRUE){st=EFI_DEVICE_ERROR;goto done;}
 st=Pair(&now,&n);if(st!=EFI_SUCCESS)goto done;
 if(CompareMem(&now,&mLease.Ref[1],sizeof(now))){st=EFI_NOT_READY;goto done;}
 mLease.Stage=5;
 done:mLease.Status=st;return st;
}
G530_REPORT *G530Report(VOID){return &mLease;}
