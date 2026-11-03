/* CB0 only. Matched owner/broker builds retain exact register comparisons.
 * CFCFG stalls a context fault; HUPCF permits subsequent transactions.
 * Neither bit repairs a translation. Faults remain terminal and retained. */
#ifndef G1341_CB0_POLICY_H
#define G1341_CB0_POLICY_H
#ifndef OGO_GPU_CB0_STALL_ON_FAULT
#define OGO_GPU_CB0_STALL_ON_FAULT 0
#endif
#if OGO_GPU_CB0_STALL_ON_FAULT != 0 && OGO_GPU_CB0_STALL_ON_FAULT != 1
#error OGO_GPU_CB0_STALL_ON_FAULT must be exactly 0 or 1
#endif
#if OGO_GPU_CB0_STALL_ON_FAULT
#define OGO_GPU_CB0_SCTLR 0x00c001e7u
#else
#define OGO_GPU_CB0_SCTLR 0x00c00067u
#endif
#endif
