/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OPEN_G27_GENI_FIFO_H
#define OPEN_G27_GENI_FIFO_H
#include <stdint.h>
#include <stddef.h>

/* Source-matched transfer core, not a Windows driver or a hardware launcher.
 * The owner supplies serialized, ordered MMIO callbacks and a qualified
 * powered/clocked/muxed engine. See README.txt before native integration.
 * A failed callback is ambiguous: it must never be automatically retried.
 */
enum g27_state { G27_IDLE, G27_ACTIVE, G27_CANCELLING, G27_ABORTING,
                 G27_DONE, G27_FAILED, G27_UNCERTAIN };
enum g27_result { G27_OK=0, G27_WAIT=1, G27_EINVAL=-1, G27_EBUSY=-2,
                  G27_ECONFIG=-3, G27_EIO=-4, G27_ESTATUS=-5,
                  G27_ECOUNT=-6, G27_ETIME=-7, G27_ECANCEL=-8 };
struct g27_io {
    void *context;
    int (*read32)(void *, uint32_t offset, uint32_t *value);
    int (*write32)(void *, uint32_t offset, uint32_t value);
    /* Ordered MMIO + device barrier. Zero means success. */
    int (*barrier)(void *);
};
struct g27_fifo {
    struct g27_io io;
    enum g27_state state;
    int failure;
    const uint8_t *tx;
    uint8_t *rx;
    uint32_t length, tx_done, rx_done, steps, step_limit, last_irq;
    uint32_t cancel_sent, abort_sent, recovered_idle;
};

int g27_init(struct g27_fifo *, struct g27_io, uint32_t step_limit);
/* Checks preconfigured 8-bit/MSB-first/mode0/CS0/FIFO geometry and idle state.
 * No clocks, pins, interrupts, rates or power configuration is performed.
 * A single final transfer uses params=0, matching spi-msm-geni.c, NOT the
 * upstream spi-geni-qcom.c manual-CS/fragmentation policy.
 */
int g27_start(struct g27_fifo *, const uint8_t *, uint8_t *, uint32_t);
int g27_step(struct g27_fifo *);
/* Explicit recovery, at most one cancel then one abort. No command replay.
 * Caller must bound recovery calls and verify idle independently afterward.
 */
int g27_cancel(struct g27_fifo *);
int g27_abort(struct g27_fifo *);

#define G27_GOODIX_VERSION_BYTES 28u
#define G27_GOODIX_READ_PREFIX 8u
int g27_goodix_read_frame(uint32_t address, uint32_t bytes,
                          uint8_t *tx, uint32_t capacity);
struct g27_goodix_version {
    char rom_pid[7], patch_pid[9];
    uint8_t rom_vid[3], patch_vid[4], sensor_id;
};
/* Fails closed for invalid checksum/PID/blank response. Does not infer IC
 * model from the DT candidate or convert a failed version read to success.
 */
int g27_goodix_decode_version(const uint8_t *, uint32_t,
                              struct g27_goodix_version *);
#endif
