/* SPDX-License-Identifier: MIT */
#ifndef G52_REPORT_H
#define G52_REPORT_H
#include <stdint.h>
#define G52_CONTACTS 10u
#define G52_PREFETCH 26u
#define G52_REPORT_MAX 90u
#define G52_TOUCH_ADDRESS 0x10274u
#define G52_TAIL_ADDRESS (G52_TOUCH_ADDRESS+G52_PREFETCH)
enum {G52_FRAME_INVALID=0,G52_FRAME_IDLE=1,G52_FRAME_REQUEST_ZERO=2,G52_FRAME_CONTACTS=3,G52_FRAME_MORE=4,G52_FRAME_UNSUPPORTED=5};
enum {G52_BAD_LENGTH=1,G52_BAD_HEADER=2,G52_BAD_COUNT=3,G52_BAD_BODY=4,G52_BAD_ID=5,G52_DUPLICATE_ID=6,G52_UNSUPPORTED_FLAGS=7,G52_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G52_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G52_CONTACT Contacts[G52_CONTACTS];
} G52_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G52DecodeReport(const uint8_t*,uint32_t,G52_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G52ReportClearable(const uint8_t*,uint32_t);
#endif
