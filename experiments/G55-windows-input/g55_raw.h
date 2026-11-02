/* SPDX-License-Identifier: MIT */
#ifndef G55_REPORT_H
#define G55_REPORT_H
#include <stdint.h>
#define G55_CONTACTS 10u
#define G55_PREFETCH 26u
#define G55_REPORT_MAX 90u
#define G55_TOUCH_ADDRESS 0x10274u
#define G55_TAIL_ADDRESS (G55_TOUCH_ADDRESS+G55_PREFETCH)
enum {G55_FRAME_INVALID=0,G55_FRAME_IDLE=1,G55_FRAME_REQUEST_ZERO=2,G55_FRAME_CONTACTS=3,G55_FRAME_MORE=4,G55_FRAME_UNSUPPORTED=5};
enum {G55_BAD_LENGTH=1,G55_BAD_HEADER=2,G55_BAD_COUNT=3,G55_BAD_BODY=4,G55_BAD_ID=5,G55_DUPLICATE_ID=6,G55_UNSUPPORTED_FLAGS=7,G55_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G55_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G55_CONTACT Contacts[G55_CONTACTS];
} G55_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G55DecodeReport(const uint8_t*,uint32_t,G55_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G55ReportClearable(const uint8_t*,uint32_t);
#endif
