/* SPDX-License-Identifier: MIT */
#ifndef G54_REPORT_H
#define G54_REPORT_H
#include <stdint.h>
#define G54_CONTACTS 10u
#define G54_PREFETCH 26u
#define G54_REPORT_MAX 90u
#define G54_TOUCH_ADDRESS 0x10274u
#define G54_TAIL_ADDRESS (G54_TOUCH_ADDRESS+G54_PREFETCH)
enum {G54_FRAME_INVALID=0,G54_FRAME_IDLE=1,G54_FRAME_REQUEST_ZERO=2,G54_FRAME_CONTACTS=3,G54_FRAME_MORE=4,G54_FRAME_UNSUPPORTED=5};
enum {G54_BAD_LENGTH=1,G54_BAD_HEADER=2,G54_BAD_COUNT=3,G54_BAD_BODY=4,G54_BAD_ID=5,G54_DUPLICATE_ID=6,G54_UNSUPPORTED_FLAGS=7,G54_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G54_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G54_CONTACT Contacts[G54_CONTACTS];
} G54_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G54DecodeReport(const uint8_t*,uint32_t,G54_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G54ReportClearable(const uint8_t*,uint32_t);
#endif
