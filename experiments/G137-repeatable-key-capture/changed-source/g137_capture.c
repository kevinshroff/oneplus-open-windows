/* SPDX-License-Identifier: MIT */
#include "g137_capture.h"
_Static_assert(sizeof(G137_STATE)==64,"fixed G137 state ABI");
_Static_assert(sizeof(G137_LEDGER)==296,"fixed internal ledger");
void G137CaptureInit(G137_LEDGER *s)
{
 if(!s)return;
 unsigned char *p=(unsigned char *)s;
 for(unsigned i=0;i<sizeof(*s);i++)p[i]=0;
}
unsigned G137CaptureCanBegin(const G137_LEDGER *s,uint64_t nonce)
{
 if(!s||!nonce||s->Phase!=G137_EMPTY||s->Count>=G137_CAPTURE_SLOTS||
    s->Retired!=s->Count||s->TotalMaps!=(uint64_t)s->Retired*5u)return 0;
 for(unsigned i=0;i<s->Count;i++)if(s->Used[i]==nonce)return 0;
 return 1;
}
unsigned G137CaptureBegin(G137_LEDGER *s,uint64_t nonce)
{
 if(!G137CaptureCanBegin(s,nonce))return 0;
 s->Used[s->Count++]=nonce;s->CurrentNonce=nonce;s->SlotMaps=0;
 s->Phase=G137_BUSY;return 1;
}
unsigned G137CaptureComplete(G137_LEDGER *s,uint32_t maps,unsigned success)
{
 if(!s)return 0;
 if(s->Phase!=G137_BUSY||!s->Count||s->Count>G137_CAPTURE_SLOTS||
    s->Retired!=s->Count-1||s->Used[s->Count-1]!=s->CurrentNonce||
    maps>5||s->TotalMaps>G137_CAPTURE_SLOTS*5u-maps||(success&&maps!=5)){
  s->Phase=G137_FAULT;return 0;
 }
 s->SlotMaps=maps;s->TotalMaps+=maps;s->Phase=success?G137_READY:G137_FAULT;
 return 1;
}
unsigned G137CaptureRetire(G137_LEDGER *s,uint64_t nonce,const void *frozen,
                           const void *echo,uint32_t bytes)
{
 if(!s||!nonce||!frozen||!echo||bytes!=G137_CAPTURE_BYTES||
    s->Count==0||s->Count>G137_CAPTURE_SLOTS)return 0;
 /* A lost successful response may be acknowledged again while the slot is
  * still empty. It must match the retained last snapshot exactly. A stale
  * acknowledgment cannot retire a newer capture, even with identical data.
  */
 unsigned repeated=s->Phase==G137_EMPTY&&s->Count==s->Retired&&
                   nonce==s->LastRetiredNonce&&nonce==s->CurrentNonce;
 if(s->Used[s->Count-1]!=s->CurrentNonce||s->SlotMaps!=5||
    s->TotalMaps!=(uint64_t)s->Count*5u)return 0;
 if(!repeated&&(s->Phase!=G137_READY||s->Count!=s->Retired+1||
               nonce!=s->CurrentNonce))return 0;
 const unsigned char *a=frozen,*b=echo;
 for(unsigned i=0;i<bytes;i++)if(a[i]!=b[i])return 0;
 if(repeated)return 2;
 s->Retired++;s->LastRetiredNonce=nonce;s->Phase=G137_EMPTY;
 return 1;
}
void G137CaptureState(const G137_LEDGER *s,G137_STATE *out)
{
 if(!s||!out)return;
 *out=(G137_STATE){sizeof(*out),1,G137_STATE_MAGIC,s->Phase,s->Count,s->Retired,
                  G137_CAPTURE_SLOTS,s->CurrentNonce,s->LastRetiredNonce,
                  s->TotalMaps,s->SlotMaps,0};
}
