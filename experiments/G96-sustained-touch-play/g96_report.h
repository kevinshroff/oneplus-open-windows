/* SPDX-License-Identifier: MIT */
#ifndef G96_REPORT_H
#define G96_REPORT_H
#include <stdint.h>
#define G96_CONTACTS 10u
#define G96_PREFETCH 26u
#define G96_REPORT_MAX 90u
#define G96_TOUCH_ADDRESS 0x10274u
#define G96_TAIL_ADDRESS (G96_TOUCH_ADDRESS+G96_PREFETCH)
enum {G96_FRAME_INVALID=0,G96_FRAME_IDLE=1,G96_FRAME_REQUEST_ZERO=2,G96_FRAME_CONTACTS=3,G96_FRAME_MORE=4,G96_FRAME_UNSUPPORTED=5};
enum {G96_BAD_LENGTH=1,G96_BAD_HEADER=2,G96_BAD_COUNT=3,G96_BAD_BODY=4,G96_BAD_ID=5,G96_DUPLICATE_ID=6,G96_UNSUPPORTED_FLAGS=7,G96_UNSUPPORTED_PEN=8};
typedef struct {uint32_t Id,X,Y,Major,Minor,Type;} G96_CONTACT;
typedef struct {
 uint32_t Kind,Error,Flags,Count,PointType,HeaderChecked,HeaderValid,BodyChecked,BodyValid,MeaningfulBytes,TailBytes,ContactMask,WithinProvisionalAxes;
 G96_CONTACT Contacts[G96_CONTACTS];
} G96_FRAME;
/* Return a complete deterministic classification. No allocation, MMIO or write. */
void G96DecodeReport(const uint8_t*,uint32_t,G96_FRAME*);
/* Recompute the classification from bytes; never authorize a clear from cached flags. */
uint32_t G96RetryablePrefix(const uint8_t*,uint32_t);
int G96ReportClearable(const uint8_t*,uint32_t);
#endif
