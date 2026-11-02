/* SPDX-License-Identifier: MIT */
#ifndef G98_REPORT_H
#define G98_REPORT_H
#include <stdint.h>
#define G98_CONTACTS 10u
#define G98_PREFETCH 26u
#define G98_REPORT_MAX 90u
#define G98_TOUCH_ADDRESS 0x10274u
#define G98_TAIL_ADDRESS (G98_TOUCH_ADDRESS+G98_PREFETCH)
enum {G98_FRAME_INVALID=0,G98_FRAME_IDLE=1,G98_FRAME_REQUEST_ZERO=2,G98_FRAME_CONTACTS=3,G98_FRAME_MORE=4,G98_FRAME_UNSUPPORTED=5,G98_FRAME_HEALTH=6};
enum {G98_BAD_LENGTH=1,G98_BAD_HEADER=2,G98_BAD_COUNT=3,G98_BAD_BODY=4,G98_BAD_ID=5,G98_DUPLICATE_ID=6,G98_UNSUPPORTED_FLAGS=7,G98_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G98_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G98_CONTACT Contacts[G98_CONTACTS];
} G98_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G98DecodeReport(const uint8_t*,uint32_t,G98_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
uint32_t G98RetryablePrefix(const uint8_t*,uint32_t);
int G98ReportClearable(const uint8_t*,uint32_t);
#endif
