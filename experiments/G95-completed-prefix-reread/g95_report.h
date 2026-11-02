/* SPDX-License-Identifier: MIT */
#ifndef G95_REPORT_H
#define G95_REPORT_H
#include <stdint.h>
#define G95_CONTACTS 10u
#define G95_PREFETCH 26u
#define G95_REPORT_MAX 90u
#define G95_TOUCH_ADDRESS 0x10274u
#define G95_TAIL_ADDRESS (G95_TOUCH_ADDRESS+G95_PREFETCH)
enum {G95_FRAME_INVALID=0,G95_FRAME_IDLE=1,G95_FRAME_REQUEST_ZERO=2,G95_FRAME_CONTACTS=3,G95_FRAME_MORE=4,G95_FRAME_UNSUPPORTED=5};
enum {G95_BAD_LENGTH=1,G95_BAD_HEADER=2,G95_BAD_COUNT=3,G95_BAD_BODY=4,G95_BAD_ID=5,G95_DUPLICATE_ID=6,G95_UNSUPPORTED_FLAGS=7,G95_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G95_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G95_CONTACT Contacts[G95_CONTACTS];
} G95_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G95DecodeReport(const uint8_t*,uint32_t,G95_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
uint32_t G95RetryablePrefix(const uint8_t*,uint32_t);
int G95ReportClearable(const uint8_t*,uint32_t);
#endif
