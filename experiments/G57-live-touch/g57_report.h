/* SPDX-License-Identifier: MIT */
#ifndef G57_REPORT_H
#define G57_REPORT_H
#include <stdint.h>
#define G57_CONTACTS 10u
#define G57_PREFETCH 26u
#define G57_REPORT_MAX 90u
#define G57_TOUCH_ADDRESS 0x10274u
#define G57_TAIL_ADDRESS (G57_TOUCH_ADDRESS+G57_PREFETCH)
enum {G57_FRAME_INVALID=0,G57_FRAME_IDLE=1,G57_FRAME_REQUEST_ZERO=2,G57_FRAME_CONTACTS=3,G57_FRAME_MORE=4,G57_FRAME_UNSUPPORTED=5};
enum {G57_BAD_LENGTH=1,G57_BAD_HEADER=2,G57_BAD_COUNT=3,G57_BAD_BODY=4,G57_BAD_ID=5,G57_DUPLICATE_ID=6,G57_UNSUPPORTED_FLAGS=7,G57_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G57_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G57_CONTACT Contacts[G57_CONTACTS];
} G57_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G57DecodeReport(const uint8_t*,uint32_t,G57_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G57ReportClearable(const uint8_t*,uint32_t);
#endif
