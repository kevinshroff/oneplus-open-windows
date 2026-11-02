/* SPDX-License-Identifier: MIT
 * GPIO83: native boot FDT TLMM base f100000 + 83 * 1000.
 * OEM kalama pinctrl binds mux[5:2], OE9, EGPIO enable12 and input0.
 * Source receipts and the boot FDT identity are retained in G120 evidence.
 */
#ifndef G121_PLAN_H
#define G121_PLAN_H
#define G121_PAGE 0x0f153000ULL
#define G121_CONTROL_OFFSET 0u
#define G121_INOUT_OFFSET 4u
#define G121_UNSUITABLE_CONTROL 0x123cu
static int G121Qualified(const ULONG samples[2][2])
{
 return samples[0][0]==samples[1][0] &&
        samples[0][1]==samples[1][1] &&
        !(samples[0][0]&G121_UNSUITABLE_CONTROL);
}
#endif
