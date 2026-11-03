/* Authored source-only fixed-purpose transaction. No native adapter supplied. */
#ifndef QTB_ONCE_H
#define QTB_ONCE_H
#include <stdint.h>
#ifndef OPEN_QTB_WITNESS
#define OPEN_QTB_WITNESS 0
#endif
enum qtb_result {QTB_DISABLED=1,QTB_REFUSED,QTB_IO,QTB_HALT_TIMEOUT,QTB_TIMEOUT,QTB_FAULT,QTB_MISMATCH,QTB_MATCH};
enum qtb_word {Q_REQ=0x410,Q_ACK=0x418,Q_IN0=0x430,Q_IN1=0x438,Q_IN2=0x440,Q_TRIGGER=0x448,Q_STATUS=0x450,Q_OUT=0x458};
/* All pointers/leases stay owned after call, even MATCH. Caller terminates before SQE1.
 * acquire pins actual native lifetime and serializes diagnostics; it must refuse a
 * consumed attempt, ungranted QTB, old firmware, missing retained196/0 vote,
 * non-current table/MDL/stream, started SQE, dirty fault or foreign halt/trigger.
 * current is normal authority; cleanup is SEPARATE poison-tolerant authority:
 * same thread/generation, code/map/remove/table/clock refs. It permits only owned
 * trigger0, exact original SCTLR and owned HALT restoration. No broad raw IOCTL.
 * Normal current must accept the exact temporary SCTLR only under this captured
 * transaction, and still reject new fault/poison. A completed check does not
 * exclude an ISR in the following instruction; native adapter serialization
 * must document that residual race, never claim immunity.
 * No callback may use BootServices or issue NPA/HFI during halt. */
struct qtb_io {
 void *ctx;
 int (*acquire)(void*,uint64_t *actual_iova,uint64_t *actual_mdl_pa);
 int (*current)(void*); int (*cleanup)(void*);
 int (*read64)(void*,unsigned,uint64_t*);
 int (*write64)(void*,unsigned,uint64_t);
 int (*read_sctlr)(void*,uint32_t*); int (*write_sctlr)(void*,uint32_t);
 /* Read-only CB0 FSR/FAR/FSYNR0 plus global/CB2 fault summary; no ACK. */
 int (*faults)(void*,uint32_t*,uint64_t*,uint32_t*,uint32_t*);
 int (*sync32)(void*); /* QTB SWID_LOW32 read + barrier, not fault clear. */
 uint64_t (*now_us)(void*);
 void (*finish)(void*,int uncertain); /* software unlock; NEVER unmap/drop leases */
};
struct qtb_report {
 enum qtb_result result,translation_result;uint32_t attempted,halt_attempted,trigger_attempted,sctlr_attempted;
 uint32_t cleanup_restored,uncertain,original_sctlr,fsr,syndrome,other_fault;
 uint32_t raw_fsr,raw_global_fsr,raw_cb2_fsr; /* native adapter, fsr above filters bit0x400 */
 uint64_t iova,expected_mdl_pa,expected_pfn,req_before,ack,status,out,far,extracted;
 uint64_t halt_us,ecats_us;
};
enum qtb_result qtb_once(const struct qtb_io*,struct qtb_report*);
#endif
