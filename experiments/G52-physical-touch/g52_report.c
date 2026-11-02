/* SPDX-License-Identifier: MIT
 * Wire layout follows the pinned stock GT9966 source. Firmware requests with
 * nonzero codes, gestures and pen modes are retained as unsupported events.
 * All checksum failures, invalid IDs and duplicate IDs are rejected.
 */
#include "g52_report.h"
static uint32_t Le16(const uint8_t*p){return(uint32_t)p[0]|((uint32_t)p[1]<<8);}
static int Sum(const uint8_t*p,uint32_t n){uint32_t i,sum=0;if(n<2)return 0;for(i=0;i<n-2;i++)sum+=p[i];return(sum&65535u)==Le16(p+n-2);}
static void Zero(G52_FRAME*r){uint32_t i;uint8_t*p=(uint8_t*)r;for(i=0;i<sizeof(*r);i++)p[i]=0;}
void G52DecodeReport(const uint8_t*b,uint32_t n,G52_FRAME*r)
{
 uint32_t i,bytes,mask=0;G52_FRAME v;if(!r)return;Zero(r);
 if(!b||n<8||n>G52_REPORT_MAX){r->Error=G52_BAD_LENGTH;return;}
 r->Flags=b[0];if(!b[0]){r->Kind=G52_FRAME_IDLE;return;}
 r->HeaderChecked=1;r->HeaderValid=Sum(b,8);if(!r->HeaderValid){r->Error=G52_BAD_HEADER;return;}
 if(b[0]==0x40&&b[2]==0){r->Kind=G52_FRAME_REQUEST_ZERO;r->MeaningfulBytes=8;return;}
 /* Only source-defined touch flags without request, gesture, idle or unknown
  * bits are handled here. Optional grip/fingerprint/health bits do not change
  * the raw coordinate layout. No edge/grip or palm policy is inferred. */
 if(!(b[0]&0x80u)||(b[0]&~0x8bu)){r->Kind=G52_FRAME_UNSUPPORTED;r->Error=G52_UNSUPPORTED_FLAGS;return;}
 r->Count=b[2]&15u;if(r->Count>G52_CONTACTS){r->Error=G52_BAD_COUNT;return;}
 bytes=8+r->Count*8+2;r->MeaningfulBytes=bytes;
 if(n<9){r->Error=G52_BAD_LENGTH;return;}
 r->PointType=b[8]&15u;if(r->PointType==1||r->PointType==3){r->Kind=G52_FRAME_UNSUPPORTED;r->Error=G52_UNSUPPORTED_PEN;return;}
 if(n<bytes){
  if(n==G52_PREFETCH&&r->Count>2){r->Kind=G52_FRAME_MORE;r->TailBytes=(r->Count-2)*8;return;}
  r->Error=G52_BAD_LENGTH;return;
 }
 r->BodyChecked=1;r->BodyValid=Sum(b+8,bytes-8);if(!r->BodyValid){r->Error=G52_BAD_BODY;return;}
 v=*r;v.WithinProvisionalAxes=1;
 for(i=0;i<v.Count;i++){
  const uint8_t*p=b+8+i*8;G52_CONTACT*c=&v.Contacts[i];uint32_t id=p[0]>>4;
  if(id>=G52_CONTACTS){r->Error=G52_BAD_ID;return;}
  if(mask&(1u<<id)){r->Error=G52_DUPLICATE_ID;return;}
  c->Id=id;c->Type=p[0]&15u;c->X=Le16(p+2);c->Y=Le16(p+4);c->Major=p[6]>p[7]?p[6]:p[7];c->Minor=p[6]<p[7]?p[6]:p[7];mask|=1u<<id;
  if(c->X>22680||c->Y>24400)v.WithinProvisionalAxes=0;
 }
 v.Kind=G52_FRAME_CONTACTS;v.ContactMask=mask;*r=v;
}
int G52ReportClearable(const uint8_t*b,uint32_t n)
{
 G52_FRAME f;G52DecodeReport(b,n,&f);return f.Kind==G52_FRAME_REQUEST_ZERO||f.Kind==G52_FRAME_CONTACTS;
}
