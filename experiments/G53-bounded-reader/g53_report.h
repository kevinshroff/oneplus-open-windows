/* SPDX-License-Identifier: MIT */
#ifndef G53_REPORT_H
#define G53_REPORT_H
#include <stdint.h>
#define G53_CONTACTS 10u
#define G53_PREFETCH 26u
#define G53_REPORT_MAX 90u
#define G53_TOUCH_ADDRESS 0x10274u
#define G53_TAIL_ADDRESS (G53_TOUCH_ADDRESS+G53_PREFETCH)
enum {G53_FRAME_INVALID=0,G53_FRAME_IDLE=1,G53_FRAME_REQUEST_ZERO=2,G53_FRAME_CONTACTS=3,G53_FRAME_MORE=4,G53_FRAME_UNSUPPORTED=5};
enum {G53_BAD_LENGTH=1,G53_BAD_HEADER=2,G53_BAD_COUNT=3,G53_BAD_BODY=4,G53_BAD_ID=5,G53_DUPLICATE_ID=6,G53_UNSUPPORTED_FLAGS=7,G53_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G53_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G53_CONTACT Contacts[G53_CONTACTS];
} G53_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G53DecodeReport(const uint8_t*,uint32_t,G53_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G53ReportClearable(const uint8_t*,uint32_t);
#endif
