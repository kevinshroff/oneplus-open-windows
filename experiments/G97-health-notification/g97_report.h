/* SPDX-License-Identifier: MIT */
#ifndef G97_REPORT_H
#define G97_REPORT_H
#include <stdint.h>
#define G97_CONTACTS 10u
#define G97_PREFETCH 26u
#define G97_REPORT_MAX 90u
#define G97_TOUCH_ADDRESS 0x10274u
#define G97_TAIL_ADDRESS (G97_TOUCH_ADDRESS+G97_PREFETCH)
enum {G97_FRAME_INVALID=0,G97_FRAME_IDLE=1,G97_FRAME_REQUEST_ZERO=2,G97_FRAME_CONTACTS=3,G97_FRAME_MORE=4,G97_FRAME_UNSUPPORTED=5,G97_FRAME_HEALTH=6};
enum {G97_BAD_LENGTH=1,G97_BAD_HEADER=2,G97_BAD_COUNT=3,G97_BAD_BODY=4,G97_BAD_ID=5,G97_DUPLICATE_ID=6,G97_UNSUPPORTED_FLAGS=7,G97_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G97_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G97_CONTACT Contacts[G97_CONTACTS];
} G97_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G97DecodeReport(const uint8_t*,uint32_t,G97_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
uint32_t G97RetryablePrefix(const uint8_t*,uint32_t);
int G97ReportClearable(const uint8_t*,uint32_t);
#endif
