/* SPDX-License-Identifier: MIT */
#ifndef G59_REPORT_H
#define G59_REPORT_H
#include <stdint.h>
#define G59_CONTACTS 10u
#define G59_PREFETCH 26u
#define G59_REPORT_MAX 90u
#define G59_TOUCH_ADDRESS 0x10274u
#define G59_TAIL_ADDRESS (G59_TOUCH_ADDRESS+G59_PREFETCH)
enum {G59_FRAME_INVALID=0,G59_FRAME_IDLE=1,G59_FRAME_REQUEST_ZERO=2,G59_FRAME_CONTACTS=3,G59_FRAME_MORE=4,G59_FRAME_UNSUPPORTED=5};
enum {G59_BAD_LENGTH=1,G59_BAD_HEADER=2,G59_BAD_COUNT=3,G59_BAD_BODY=4,G59_BAD_ID=5,G59_DUPLICATE_ID=6,G59_UNSUPPORTED_FLAGS=7,G59_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G59_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G59_CONTACT Contacts[G59_CONTACTS];
} G59_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G59DecodeReport(const uint8_t*,uint32_t,G59_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
int G59ReportClearable(const uint8_t*,uint32_t);
#endif
