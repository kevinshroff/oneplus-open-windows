/* SPDX-License-Identifier: MIT */
#ifndef G56_REPORT_H
#define G56_REPORT_H
#include <stdint.h>
#define G56_CONTACTS 10u
#define G56_PREFETCH 26u
#define G56_REPORT_MAX 90u
#define G56_TOUCH_ADDRESS 0x10274u
#define G56_TAIL_ADDRESS (G56_TOUCH_ADDRESS+G56_PREFETCH)
enum {G56_FRAME_INVALID=0,G56_FRAME_IDLE=1,G56_FRAME_REQUEST_ZERO=2,G56_FRAME_CONTACTS=3,G56_FRAME_MORE=4,G56_FRAME_UNSUPPORTED=5};
enum {G56_BAD_LENGTH=1,G56_BAD_HEADER=2,G56_BAD_COUNT=3,G56_BAD_BODY=4,G56_BAD_ID=5,G56_DUPLICATE_ID=6,G56_UNSUPPORTED_FLAGS=7,G56_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G56_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G56_CONTACT Contacts[G56_CONTACTS];
} G56_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G56DecodeReport(const uint8_t*,uint32_t,G56_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G56ReportClearable(const uint8_t*,uint32_t);
#endif
