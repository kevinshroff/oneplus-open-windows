/* SPDX-License-Identifier: MIT
 * Wire layout follows the pinned stock GT9966 source. Firmware requests with
 * nonzero codes, gestures and pen modes are retained as unsupported events.
 * Coordinate-bearing packets require both checksums and valid unique IDs.
 * Zero-count touch headers carry release semantics; trailing bytes are unused.
 */
#include "g59_report.h"
static uint32_t Le16(const uint8_t*p){return(uint32_t)p[0]|((uint32_t)p[1]<<8);}
static int Sum(const uint8_t*p,uint32_t n){uint32_t i,sum=0;if(n<2)return 0;for(i=0;i<n-2;i++)sum+=p[i];return(sum&65535u)==Le16(p+n-2);}
static void Zero(G59_FRAME*r){uint32_t i;uint8_t*p=(uint8_t*)r;for(i=0;i<sizeof(*r);i++)p[i]=0;}
void G59DecodeReport(const uint8_t*b,uint32_t n,G59_FRAME*r)
{
 uint32_t i,bytes,mask=0;G59_FRAME v;if(!r)return;Zero(r);
 if(!b||n<8||n>G59_REPORT_MAX){r->Error=G59_BAD_LENGTH;return;}
 r->Flags=b[0];if(!b[0]){r->Kind=G59_FRAME_IDLE;return;}
 r->HeaderChecked=1;r->HeaderValid=Sum(b,8);if(!r->HeaderValid){r->Error=G59_BAD_HEADER;return;}
 if(b[0]==0x40&&b[2]==0){r->Kind=G59_FRAME_REQUEST_ZERO;r->MeaningfulBytes=8;return;}
 /* Only source-defined touch flags without request, gesture, idle or unknown
  * bits are handled here. Optional grip/fingerprint/health bits do not change
  * the raw coordinate layout. No edge/grip or palm policy is inferred. */
 if(!(b[0]&0x80u)||(b[0]&~0x8bu)){r->Kind=G59_FRAME_UNSUPPORTED;r->Error=G59_UNSUPPORTED_FLAGS;return;}
 r->Count=b[2]&15u;if(r->Count>G59_CONTACTS){r->Error=G59_BAD_COUNT;return;}
 /* Stock get_touch_points handles count0 as UP before point access. Native
  * G53 captured a valid zero-count header followed by FFFF. There are no
  * coordinates here: do not interpret trailing bytes as a point or claim a
  * body checksum. Header integrity remains mandatory. */
 if(r->Count==0){r->Kind=G59_FRAME_CONTACTS;r->MeaningfulBytes=8;r->WithinProvisionalAxes=1;return;}
 bytes=8+r->Count*8+2;r->MeaningfulBytes=bytes;
 if(n<9){r->Error=G59_BAD_LENGTH;return;}
 r->PointType=b[8]&15u;if(r->PointType==1||r->PointType==3){r->Kind=G59_FRAME_UNSUPPORTED;r->Error=G59_UNSUPPORTED_PEN;return;}
 if(n<bytes){
  if(n==G59_PREFETCH&&r->Count>2){r->Kind=G59_FRAME_MORE;r->TailBytes=(r->Count-2)*8;return;}
  r->Error=G59_BAD_LENGTH;return;
 }
 r->BodyChecked=1;r->BodyValid=Sum(b+8,bytes-8);if(!r->BodyValid){r->Error=G59_BAD_BODY;return;}
 v=*r;v.WithinProvisionalAxes=1;
 for(i=0;i<v.Count;i++){
  const uint8_t*p=b+8+i*8;G59_CONTACT*c=&v.Contacts[i];uint32_t id=p[0]>>4;
  if(id>=G59_CONTACTS){r->Error=G59_BAD_ID;return;}
  if(mask&(1u<<id)){r->Error=G59_DUPLICATE_ID;return;}
  c->Id=id;c->Type=p[0]&15u;c->X=Le16(p+2);c->Y=Le16(p+4);c->Major=p[6]>p[7]?p[6]:p[7];c->Minor=p[6]<p[7]?p[6]:p[7];mask|=1u<<id;
  if(c->X>22680||c->Y>24400)v.WithinProvisionalAxes=0;
 }
 v.Kind=G59_FRAME_CONTACTS;v.ContactMask=mask;*r=v;
}
int G59ReportClearable(const uint8_t*b,uint32_t n)
{
 G59_FRAME f;G59DecodeReport(b,n,&f);return f.Kind==G59_FRAME_REQUEST_ZERO||f.Kind==G59_FRAME_CONTACTS;
}
