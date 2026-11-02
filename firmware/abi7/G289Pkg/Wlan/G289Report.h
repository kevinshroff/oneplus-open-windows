/* SPDX-License-Identifier: GPL-2.0-only -- exact OWIF/NVS ABI1. */
#ifndef G289_REPORT_H
#define G289_REPORT_H
#include "g289_boot_votes.h"
#include "g289_rc0.h"
typedef struct {
 uint32_t Magic,Version,Bytes,Stage;
 uint64_t Status;
 uint32_t Attempted,ExitedBootServices,Protected,RetainedUntilReset;
 uint32_t IcbProfile,IcbAttempted,IcbReturned,CornerMask;
 uint32_t Initial[2][24],BeforeRc[2][24];
 G289_BOOT_VOTES Votes;
 G289_RC0 Rc;
 uint32_t PdcFrames,ClockNext,ClockFault,ClockUncertain;
 uint64_t ClockFirst,PinFirst,QmpFirst;
 uint32_t XoAddress,XoRequestId;
}REPORT;
#pragma pack(1)
typedef struct {
 uint32_t Signature,Length;uint8_t Revision,Checksum;uint8_t Oem[6];uint8_t OemId[8];
 uint32_t OemRevision,Creator,CreatorRevision;uint64_t Address;uint32_t Bytes,Abi;
}TABLE;
#pragma pack()
_Static_assert(sizeof(REPORT)==840,"report ABI1");
_Static_assert(sizeof(TABLE)==52,"OWIF ABI1");
_Static_assert(offsetof(REPORT,Magic)==0,"report Magic");
_Static_assert(offsetof(REPORT,Version)==4,"report Version");
_Static_assert(offsetof(REPORT,Bytes)==8,"report Bytes");
_Static_assert(offsetof(REPORT,Stage)==12,"report Stage");
_Static_assert(offsetof(REPORT,Status)==16,"report Status");
_Static_assert(offsetof(REPORT,Attempted)==24,"report Attempted");
_Static_assert(offsetof(REPORT,ExitedBootServices)==28,"report ExitedBootServices");
_Static_assert(offsetof(REPORT,Protected)==32,"report Protected");
_Static_assert(offsetof(REPORT,RetainedUntilReset)==36,"report RetainedUntilReset");
_Static_assert(offsetof(REPORT,IcbProfile)==40,"report IcbProfile");
_Static_assert(offsetof(REPORT,IcbAttempted)==44,"report IcbAttempted");
_Static_assert(offsetof(REPORT,IcbReturned)==48,"report IcbReturned");
_Static_assert(offsetof(REPORT,CornerMask)==52,"report CornerMask");
_Static_assert(offsetof(REPORT,Initial)==56,"report Initial");
_Static_assert(offsetof(REPORT,BeforeRc)==248,"report BeforeRc");
_Static_assert(offsetof(REPORT,Votes)==440,"report Votes");
_Static_assert(offsetof(REPORT,Rc)==704,"report Rc");
_Static_assert(offsetof(REPORT,PdcFrames)==792,"report PdcFrames");
_Static_assert(offsetof(REPORT,ClockNext)==796,"report ClockNext");
_Static_assert(offsetof(REPORT,ClockFault)==800,"report ClockFault");
_Static_assert(offsetof(REPORT,ClockUncertain)==804,"report ClockUncertain");
_Static_assert(offsetof(REPORT,ClockFirst)==808,"report ClockFirst");
_Static_assert(offsetof(REPORT,PinFirst)==816,"report PinFirst");
_Static_assert(offsetof(REPORT,QmpFirst)==824,"report QmpFirst");
_Static_assert(offsetof(REPORT,XoAddress)==832,"report XoAddress");
_Static_assert(offsetof(REPORT,XoRequestId)==836,"report XoRequestId");
#endif
