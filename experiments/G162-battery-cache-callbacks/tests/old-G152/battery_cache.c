/* SPDX-License-Identifier: MIT */
#include "battery_cache.h"

void ObInitialize(OB_CACHE *c) { if(c) { OB_CACHE empty={0}; *c=empty; } }
void ObInvalidate(OB_CACHE *c,uint32_t *notify)
{
 if(!c)return;
 if(c->Present)c->PendingNotify|=3;
 c->Present=0; c->EndUs=0;
 for(unsigned i=0;i<2;i++) { OB_READING empty={0}; c->Reading[i]=empty; c->Notify[i].Armed=0; }
 if(notify){*notify|=c->PendingNotify;c->PendingNotify=0;}
}
int ObBeginOwner(OB_CACHE *c,uint64_t epoch,uint32_t *notify)
{
 if(notify)*notify=0;
 if(!c||!notify||!epoch)return OB_ARGUMENT;
 if(epoch<=c->OwnerEpoch)return OB_OLD_OWNER;
 ObInvalidate(c,notify);c->OwnerEpoch=epoch;c->LastSequence=0;
 return c->Exhausted?OB_EXHAUSTED:OB_OK;
}
static void Expire(OB_CACHE *c,uint64_t now)
{ if(c->Present&&(now<c->EndUs||now-c->EndUs>OB_MAX_AGE_US))ObInvalidate(c,0); }
int ObTick(OB_CACHE *c,uint64_t now,uint32_t *notify)
{
 if(notify)*notify=0;
 if(!c||!notify)return OB_ARGUMENT;
 Expire(c,now);*notify=c->PendingNotify;c->PendingNotify=0;
 return c->Present?OB_OK:OB_NO_DEVICE;
}
static int ValidWords(const uint32_t *w)
{
 for(unsigned j=0;j<10;j++)if(w[j]>65535)return 0;
 /* Native-qualified type and firmware. Bounds reject corrupt transport data;
  * they are not thermal limits or permission to charge the battery. */
 return w[0]==0x6002&&w[1]==0x0602&&w[2]==0x0200&&
  w[3]>=2000&&w[3]<=4000&&w[4]>=1000&&w[4]<=6000&&
  w[7]>0&&w[6]<=w[7]&&w[9]<=100;
}
static int32_t SignedWord(uint32_t word)
{ return word&0x8000u?(int32_t)word-65536:(int32_t)word; }
static int ValidPower(const OB_BATCH *b,unsigned i)
{
 uint32_t known=b->PowerKnown[i],state=b->PowerState[i];
 int32_t rate=SignedWord(b->Words[i][8]);
 if(known>1||state>15||(!known&&state))return 0;
 if(!known)return 1;
 if((state&OB_CHARGING)&&(state&OB_DISCHARGING))return 0;
 if(rate<0&&!(state&OB_DISCHARGING))return 0;
 if(rate>0&&!(state&OB_CHARGING))return 0;
 if((state&OB_CHARGING)&&rate<0)return 0;
 if((state&OB_DISCHARGING)&&rate>0)return 0;
 /* Online is a system claim, not proof from one local gauge or cable. */
 if((state&OB_ONLINE)&&(!b->PowerKnown[0]||!b->PowerKnown[1]||
    SignedWord(b->Words[0][8])<0||SignedWord(b->Words[1][8])<0||
    (b->PowerState[0]&OB_DISCHARGING)||(b->PowerState[1]&OB_DISCHARGING)))return 0;
 return 1;
}
static int Outside(const OB_READING *r,const OB_NOTIFY *n)
{ return !r->PowerKnown||(r->PowerState&~n->PowerState)||r->RemainingMah<n->Low||r->RemainingMah>n->High; }
int ObPublish(OB_CACHE *c,const OB_BATCH *b,uint64_t now,uint32_t *notify)
{
 OB_READING next[2];uint32_t expired=0;
 if(notify)*notify=0;
 if(!c||!b||!notify)return OB_ARGUMENT;
 if(!c->OwnerEpoch||b->OwnerEpoch!=c->OwnerEpoch)return OB_OLD_OWNER;
 if(!b->Sequence||b->Sequence<=c->LastSequence)return OB_OLD_INPUT;
 /* Reserve sequence before validation: a failed operation is not replayable. */
 c->LastSequence=b->Sequence;
 ObTick(c,now,&expired);*notify|=expired;
 if(c->Exhausted)return OB_EXHAUSTED;
 if(b->OwnerQualified!=1||b->Complete!=1||!b->BeginUs||b->EndUs<b->BeginUs||
    b->EndUs-b->BeginUs>OB_MAX_BATCH_US||now<b->EndUs||now-b->EndUs>OB_MAX_AGE_US||
    (c->Present&&b->EndUs<c->EndUs)||!ValidWords(b->Words[0])||!ValidWords(b->Words[1])||
    !ValidPower(b,0)||!ValidPower(b,1)) {
  ObInvalidate(c,notify);return OB_INVALID_DATA;
 }
 if(!c->Present&&c->LastTag==UINT32_MAX) {c->Exhausted=1;return OB_EXHAUSTED;}
 if(!c->Present)c->LastTag++;
 for(unsigned i=0;i<2;i++) {
  const uint32_t *w=b->Words[i];
  next[i]=(OB_READING){c->LastTag,w[3],w[4],w[6],w[7],w[9],SignedWord(w[8]),b->PowerKnown[i],b->PowerState[i]};
  if(!c->Present)*notify|=1u<<i;
  else if(c->Reading[i].FullMah!=next[i].FullMah)*notify|=1u<<i;
  if(c->Notify[i].Armed&&Outside(next+i,c->Notify+i)) { *notify|=1u<<i;c->Notify[i].Armed=0; }
 }
 c->Reading[0]=next[0];c->Reading[1]=next[1];c->EndUs=b->EndUs;c->Present=1;
 return OB_OK;
}
int ObQueryTag(OB_CACHE *c,unsigned gauge,uint64_t now,uint32_t *tag)
{
 if(tag)*tag=0;
 if(!c||!tag||gauge>1)return OB_ARGUMENT;
 Expire(c,now);if(!c->Present)return OB_NO_DEVICE;
 *tag=c->Reading[gauge].Tag;return OB_OK;
}
int ObRead(OB_CACHE *c,unsigned gauge,uint32_t tag,uint64_t now,OB_READING *out)
{
 uint32_t actual;OB_READING empty={0};if(out)*out=empty;
 if(!out)return OB_ARGUMENT;
 int rc=ObQueryTag(c,gauge,now,&actual);if(rc)return rc;
 if(!tag||tag!=actual)return OB_NO_DEVICE;
 *out=c->Reading[gauge];return OB_OK;
}
int ObSetNotify(OB_CACHE *c,unsigned gauge,uint32_t tag,uint64_t now,
 uint32_t state,uint32_t low,uint32_t high,uint32_t *notify)
{
 OB_READING r;if(notify)*notify=0;
 if(!notify||state>15||low>high)return OB_ARGUMENT;
 int rc=ObRead(c,gauge,tag,now,&r);if(rc)return rc;
 if(!r.PowerKnown)return OB_NOT_READY;
 c->Notify[gauge]=(OB_NOTIFY){1,state,low,high};
 if(Outside(&r,c->Notify+gauge)) { *notify|=1u<<gauge;c->Notify[gauge].Armed=0; }
 return OB_OK;
}
int ObDisableNotify(OB_CACHE *c,unsigned gauge)
{
 if(!c||gauge>1)return OB_ARGUMENT;
 c->Notify[gauge].Armed=0;return c->Present?OB_OK:OB_NO_DEVICE;
}
