/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Original Windows-oriented orchestration; modern HFI contract and permissive
 * encoder/parser provenance are recorded in NOTICE.md. No native owner here. */
#ifndef G190_BACKEND_H
#define G190_BACKEND_H
#include <stddef.h>
#include <stdint.h>
#include "vendor/AdrenoFirmware.h"
#include "vendor/AdrenoHfiEncode.h"

#define G190_HFI_BYTES 16384u
#define G190_QUEUE_WORDS 1024u
#define G190_CM3_FAULT (UINT32_C(1) << 23)
/* Exact observed OnePlus Open cold-owner all-masked AO policy; not a
 * universal register-width/bit6 definition. Full32bit readback is required. */
#define G190_AO_MASK_ALL UINT32_C(0x7f)
/* Pinned Open preboot proof/configuration policy, independently bounded.
 * boot_us remains solely the actual reset/FW-ready handshake budget. */
#define G190_PREBOOT_US UINT64_C(5000000)
enum {G190_BOOT_NONE,G190_BOOT_PREBOOT_BEGIN,G190_BOOT_BOARD_DONE,
 G190_BOOT_STATE_CHECKED,G190_BOOT_CONFIG_POSTED,G190_BOOT_CONFIG_VERIFIED,
 G190_BOOT_RESET_BOUNDARY,G190_BOOT_READY};
#define G190_AO_FATAL UINT32_C(0x29) /* WDOG_BITE0, FENCE_ERR3, HOST_AHB_BUS_ERROR5 */
#define G190_MAX_IMAGE_BYTES (1024u * 1024u)

/* Byte offsets relative to the qualified GMU CORE window, not a CPU PA and
 * not the downstream DT's resource beginning 0x2000 earlier. */
enum g190_reg {
    G190_CM3_RESET = 0x5000u * 4, G190_FW_RESULT = 0x501cu * 4,
    G190_BOOT_CONFIG = 0x5001u * 4, G190_DTCM_VERSION = (0x1c00u + 0xff8u) * 4,
    G190_HFI_STATUS = 0x5180u * 4, G190_HFI_QTBL_INFO = 0x5184u * 4,
    G190_HFI_QTBL_ADDR = 0x5185u * 4, G190_HFI_INIT = 0x5186u * 4,
    G190_G2H_CLEAR = 0x5191u * 4, G190_G2H_INFO = 0x5192u * 4,
    G190_G2H_MASK = 0x5193u * 4, G190_H2G_SET = 0x5194u * 4,
    G190_AO_CLEAR = 0x9304u * 4, G190_AO_MASK = 0x9306u * 4,
    G190_AO_STATUS = 0x9305u * 4
};
typedef enum { G190_ACQUIRE, G190_PUBLISH, G190_COMPLETE } g190_barrier;
typedef enum {
    G190_OK, G190_PENDING, G190_ARGUMENT, G190_STATE, G190_STALE_EPOCH,
    G190_LEASE_LOST, G190_CANCELLED, G190_CLOCK, G190_TIMEOUT, G190_IO,
    G190_FIRMWARE, G190_CORRUPT, G190_BUSY, G190_NO_SPACE,
    G190_FW_ERROR, G190_SEQUENCE_EXHAUSTED, G190_POISONED, G190_UNSUPPORTED
} g190_status;
typedef enum {
    G190_NEW, G190_STOPPED, G190_LOADED, G190_FW_READY, G190_BOARD_READY, G190_HFI_READY,
    G190_STARTUP_COMPLETE, G190_FAILED
} g190_phase;

/* All callbacks execute under one serialized PASSIVE-level owner. They must
 * be bounded, non-reentrant, and report real failures. No callback is allowed
 * to synthesize readiness/ACKs on hardware. Test doubles are host-only.
 * prove_stopped must cover GMU/GPU DMA, shared queues, SMMU/TLB drain and all
 * pending host callbacks for this generation; RESET==1 alone is insufficient.
 * Every mapped extent stays pinned until a NEW external stop witness, even
 * after timeout/cancel/failure. The core never frees a mapping or allocation. */
typedef struct {
    void *cookie;
    int (*lease)(void *, uint64_t generation);
    int (*prove_stopped)(void *, uint64_t stop_serial, uint64_t generation);
    int (*read_reg)(void *, uint32_t byte_offset, uint32_t *value);
    int (*write_reg)(void *, uint32_t byte_offset, uint32_t value);
    int (*barrier)(void *, g190_barrier);
    int (*now_us)(void *, uint64_t *);
    int (*wait_us)(void *, uint32_t);
    int (*cancelled)(void *);
    int (*verify_sha256)(void *, const uint8_t *, size_t, const uint8_t expected[32]);
    /* region1=ITCM[0,0x4000),2=ICACHE[0x4000,0x1000000),
     * 3=DTCM[0x10004000,0x10008000). Offset is relative to that region.
     * Adapter owns full zeroed/cache-qualified backing, not just file payload. */
    int (*firmware_write)(void *, uint32_t region, uint32_t offset, uint32_t value);
    int (*firmware_read)(void *, uint32_t region, uint32_t offset, uint32_t *value);
    /* Qualify/setup clocks, RSC/PDC, FAL/TCM retention and board chip-ID
     * configuration; MUST keep CM3 reset asserted and IRQs masked. */
    int (*configure_board_stopped)(void *);
} g190_ops;

typedef struct {
    uint32_t polls_per_operation; /*1..65536, also bounds a stopped clock */
    uint32_t wait_us;             /*1..1000*/
    uint64_t load_us, boot_us, command_us, startup_us; /*nonzero, <=60s*/
} g190_limits;
typedef struct {
    const uint8_t *bytes; size_t size;
    size_t expected_blocks; /* exact count from an independently pinned image */
    uint8_t sha256[32];     /* identity pin, NOT secure-firmware authentication */
} g190_image;
typedef struct {
    uint32_t words[16], word_count, firmware_error, wire_header;
} g190_reply;
typedef struct {
    g190_ops ops; g190_limits limits;
    volatile uint32_t *shared; uint32_t iova;
    uint64_t epoch, generation, stop_serial, last_us, command_begin_us;
    uint32_t sequence, pending_header, poll_count;
    uint32_t skipped_acks, asynchronous_error, startup_acked, startup_attempted;
    uint32_t resources_must_retain, reset_released, time_seen;
    /* Last successful observations, never synthetic current hardware state.
     * stage1=stopped,2=load,3=board setup,4=reset released,5=FW ready,
     * 6=HFI ready,7..10=startup command,11=complete. */
    uint32_t stage, failure_stage, last_register, last_register_value;
    uint32_t last_register_valid, last_register_write, last_ao, last_g2h;
    uint32_t firmware_version, firmware_init_result, hfi_status;
    uint32_t firmware_region, firmware_offset, firmware_expected, firmware_observed;
    uint32_t firmware_observed_valid;
    g190_phase phase; g190_status failure;
    AdrenoFirmwareBlock blocks[32]; size_t block_count;
    /* Actual sampled times, zero until observed; last_us is failure/poll time.
     * No new register reads or hardware-success inference from these fields. */
    uint64_t preboot_begin_us, preboot_board_us, preboot_done_us, firmware_begin_us;
    uint32_t boot_checkpoint;
} g190_backend;

/* Objects, shared queue, image/config and outputs must be disjoint and pinned.
 * Zero-initialize backend once. No re-init of a live/failed backend permitted.
 * Shared memory: exclusive 16KiB CPU extent,4KiB-aligned, coherent with GMU,
 * native4KiB GMU IOVA mapping below4GiB. These are adapter obligations. */
g190_status g190_initialize(g190_backend *, const g190_ops *, const g190_limits *,
    volatile uint32_t *shared, size_t bytes, uint64_t iova);
g190_status g190_begin_epoch(g190_backend *, uint64_t expected_epoch,
    uint64_t fresh_stop_serial, uint64_t generation);
g190_status g190_load_image(g190_backend *, uint64_t epoch, const g190_image *);
g190_status g190_boot_firmware(g190_backend *, uint64_t epoch);
/* Only after the concrete platform FW-ready stage has committed BOARD_READY. */
g190_status g190_start_hfi(g190_backend *, uint64_t epoch);
g190_status g190_submit(g190_backend *, uint64_t epoch, uint32_t id,
    const uint32_t *payload, size_t words);
g190_status g190_poll(g190_backend *, uint64_t epoch, g190_reply *);
g190_status g190_startup(g190_backend *, uint64_t epoch, const AdrenoHfiStartupConfig *);
/* Pure layout preflight. No hardware callbacks; count=0 on failure. Output
 * entries are committed only on success. Format/identity pin is not signing. */
g190_status g190_plan_image(const g190_image *,AdrenoFirmwareBlock *,size_t capacity,size_t *count);
/* Pure final input validation before a concrete platform split boot. */
g190_status g190_preflight_run(g190_backend *,uint64_t expected_epoch,
    const g190_image *,const AdrenoHfiStartupConfig *);
/* Pure ISR ownership rule; actual backend keeps both interrupt banks masked.
 * A future ISR may acknowledge ONLY its owned CM3 bit, never MSGQ/OOB ACKs. */
uint32_t g190_fault_ack_bits(uint32_t observed);
#endif
