/* SPDX-License-Identifier: MIT
 * Windows touch lifecycle: retain released IDs/last coordinates for one UP
 * report; contact count includes those records. Confidence remains set on UP.
 * Contract: https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchscreen-required-hid-top-level-collections
 * Raw orientation is the three-capture G52 result; no edge calibration is claimed.
 */
#include "g57hid_lifecycle.h"
#include "g57_report.h"
static void Zero(G57HID_PLAN*p){uint32_t i;uint8_t*b=(uint8_t*)p;for(i=0;i<sizeof(*p);i++)b[i]=0;}
static int Valid(const G57HID_STATE*s){uint32_t i;if(!s||(s->Mask&~1023u))return 0;for(i=0;i<10;i++)if(s->Mask&(1u<<i))if(s->Last[i].X>G57HID_MAX_X||s->Last[i].Y>G57HID_MAX_Y)return 0;return 1;}
static int Build(const G57HID_STATE*s,uint32_t mask,const G57HID_POSITION*current,uint16_t scan,G57HID_PLAN*p)
{
 uint32_t id,slot=0,all;if(!Valid(s)||(mask&~1023u)){p->Error=1;return 0;}all=s->Mask|mask;
 p->FromGeneration=s->Generation;p->Next=*s;
 if(!all)return 1;
 p->HaveReport=1;p->Next.Generation=s->Generation+1;p->Next.Mask=mask;p->Report[0]=1;
 for(id=0;id<10;id++)p->Report[2+id*6]=(uint8_t)id;
 for(id=0;id<10;id++)if(all&(1u<<id)){
  uint32_t present=mask&(1u<<id);G57HID_POSITION q=present?current[id]:s->Last[id];uint32_t at=1+slot*6;
  if(q.X>G57HID_MAX_X||q.Y>G57HID_MAX_Y){p->Error=2;return 0;}
  p->Report[at]=(uint8_t)(present?3:2);p->Report[at+1]=(uint8_t)id;p->Report[at+2]=(uint8_t)q.X;p->Report[at+3]=(uint8_t)(q.X>>8);p->Report[at+4]=(uint8_t)q.Y;p->Report[at+5]=(uint8_t)(q.Y>>8);
  if(present)p->Next.Last[id]=q;slot++;
 }
 p->Report[61]=(uint8_t)scan;p->Report[62]=(uint8_t)(scan>>8);p->Report[63]=(uint8_t)slot;return 1;
}
int G57HIDPrepare(const G57HID_STATE*s,const uint8_t*raw,uint32_t n,uint16_t scan,G57HID_PLAN*p)
{
 G57_FRAME f;G57HID_POSITION positions[10]={{0}};uint32_t i;if(!p)return 0;Zero(p);
 if(!Valid(s)){p->Error=1;return 0;}p->FromGeneration=s->Generation;p->Next=*s;G57DecodeReport(raw,n,&f);
 if(f.Kind==G57_FRAME_IDLE||f.Kind==G57_FRAME_REQUEST_ZERO)return 1;
 if(f.Kind!=G57_FRAME_CONTACTS||f.Flags!=0x80||!f.WithinProvisionalAxes){p->Error=3;return 0;}
 for(i=0;i<f.Count;i++){
  const G57_CONTACT*c=&f.Contacts[i];if(c->Type!=0&&c->Type!=2){p->Error=4;return 0;}
  positions[c->Id].X=(c->Y*G57HID_MAX_X+12200u)/24400u;
  positions[c->Id].Y=((22680u-c->X)*G57HID_MAX_Y+11340u)/22680u;
 }
 return Build(s,f.ContactMask,positions,scan,p);
}
int G57HIDReleaseAll(const G57HID_STATE*s,uint16_t scan,G57HID_PLAN*p){if(!p)return 0;Zero(p);return Build(s,0,0,scan,p);}
int G57HIDCommit(G57HID_STATE*s,const G57HID_PLAN*p)
{
 if(!s||!p||!p->HaveReport||p->Error||!Valid(s)||p->FromGeneration!=s->Generation||p->Next.Generation!=s->Generation+1||!Valid(&p->Next))return 0;
 *s=p->Next;return 1;
}
