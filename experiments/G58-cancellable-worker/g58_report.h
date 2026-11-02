/* SPDX-License-Identifier: MIT */
#ifndef G58_REPORT_H
#define G58_REPORT_H
#include <stdint.h>
#define G58_CONTACTS 10u
#define G58_PREFETCH 26u
#define G58_REPORT_MAX 90u
#define G58_TOUCH_ADDRESS 0x10274u
#define G58_TAIL_ADDRESS (G58_TOUCH_ADDRESS+G58_PREFETCH)
enum {G58_FRAME_INVALID=0,G58_FRAME_IDLE=1,G58_FRAME_REQUEST_ZERO=2,G58_FRAME_CONTACTS=3,G58_FRAME_MORE=4,G58_FRAME_UNSUPPORTED=5};
enum {G58_BAD_LENGTH=1,G58_BAD_HEADER=2,G58_BAD_COUNT=3,G58_BAD_BODY=4,G58_BAD_ID=5,G58_DUPLICATE_ID=6,G58_UNSUPPORTED_FLAGS=7,G58_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G58_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G58_CONTACT Contacts[G58_CONTACTS];
} G58_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G58DecodeReport(const uint8_t*,uint32_t,G58_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G58ReportClearable(const uint8_t*,uint32_t);
#endif
