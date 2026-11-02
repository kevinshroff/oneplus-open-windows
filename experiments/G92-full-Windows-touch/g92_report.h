/* SPDX-License-Identifier: MIT */
#ifndef G92_REPORT_H
#define G92_REPORT_H
#include <stdint.h>
#define G92_CONTACTS 10u
#define G92_PREFETCH 26u
#define G92_REPORT_MAX 90u
#define G92_TOUCH_ADDRESS 0x10274u
#define G92_TAIL_ADDRESS (G92_TOUCH_ADDRESS+G92_PREFETCH)
enum {G92_FRAME_INVALID=0,G92_FRAME_IDLE=1,G92_FRAME_REQUEST_ZERO=2,G92_FRAME_CONTACTS=3,G92_FRAME_MORE=4,G92_FRAME_UNSUPPORTED=5};
enum {G92_BAD_LENGTH=1,G92_BAD_HEADER=2,G92_BAD_COUNT=3,G92_BAD_BODY=4,G92_BAD_ID=5,G92_DUPLICATE_ID=6,G92_UNSUPPORTED_FLAGS=7,G92_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G92_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G92_CONTACT Contacts[G92_CONTACTS];
} G92_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G92DecodeReport(const uint8_t*,uint32_t,G92_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G92ReportClearable(const uint8_t*,uint32_t);
#endif
