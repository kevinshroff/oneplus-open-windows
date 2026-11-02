#ifndef G98_RSC_PROFILE_H
#define G98_RSC_PROFILE_H
#include <stdint.h>
/* Two exact observed idle command payloads. Their origin/meaning is not
 * inferred. These are staged RSC command words,not CPU MMIO addresses. */
static inline int G98RscBaselinePayload(uint32_t address,uint32_t data)
{
 return (address==0x50008u&&data==0x60000001u)||
        (address==0x50000u&&data==0x600626acu);
}
#endif
