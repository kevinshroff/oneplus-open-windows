/* SPDX-License-Identifier: MIT
 * Always-on battery charging & safety watchdog policy for OnePlus Open (SM8550).
 * Uses real dual ZY0602 I2C gauge readings + ADSP GLINK UsbOnline/control.
 */
#ifndef OPEN_CK_POLICY_H
#define OPEN_CK_POLICY_H
#include <stdint.h>

/* Safety thresholds (real ZY0602 physical gauge readings) */
#define CK_TEMP_MIN_DK      2781u  /*  5.0 C hard cutoff */
#define CK_TEMP_MAX_DK      3171u  /* 44.0 C hard cutoff */
#define CK_TEMP_REC_MIN_DK  2831u  /* 10.0 C recovery hysteresis */
#define CK_TEMP_REC_MAX_DK  3126u  /* 39.5 C recovery hysteresis */
#define CK_VOLT_HARD_MAX_MV 4480u  /* hard overvoltage cutoff */
#define CK_VOLT_IMBAL_MV    300u   /* max cell-to-cell voltage delta */

/* Everyday full-charge hysteresis (charges to ~100% safely, tops up <= 95%) */
#define CK_SOC_STOP_PCT     99u    /* pause charging at >= 99% */
#define CK_SOC_START_PCT    95u    /* resume charging at <= 95% */
#define CK_VOLT_STOP_MV     4440u  /* pause charging at >= 4.44 V */
#define CK_VOLT_START_MV    4340u  /* resume charging at <= 4.34 V */

/* Timing (microseconds) */
#define CK_POLL_INTERVAL_US UINT64_C(10000000) /* 10s telemetry poll */
#define CK_RESTART_GAP_US   UINT64_C(5000000)  /* proven 5s off->on gap (G177) */
#define CK_RETRY_COOLDOWN_US UINT64_C(30000000)/* 30s bounded retry cooldown */
#define CK_MAX_GAUGE_ERRS   3u

enum {
    CK_ST_IDLE = 0,        /* waiting / monitoring */
    CK_ST_SET_FV,          /* sending FV = 4470 mV */
    CK_ST_PRE_OFF,         /* sending prop 24 = 0 before 5s gap */
    CK_ST_GAP_WAIT,        /* waiting 5s before prop 24 = 1 */
    CK_ST_ENABLING,        /* sending prop 24 = 1 */
    CK_ST_CHARGING,        /* actively charging, polling every 10s */
    CK_ST_DISABLING,       /* sending prop 24 = 0 (stop/safety/pause) */
    CK_ST_HOLD_FULL,       /* reached >=85% / 4.30V, waiting to drop <=75% */
    CK_ST_SAFETY_HOLD,     /* tripped temp/volt/imbal/gauge cutoff */
    CK_ST_PAUSED           /* operator-paused via IOCTL */
};

enum {
    CK_SAFE_OK = 0,
    CK_SAFE_NO_USB,
    CK_SAFE_TEMP,
    CK_SAFE_OVERVOLT,
    CK_SAFE_IMBALANCE,
    CK_SAFE_GAUGE_ERR,
    CK_SAFE_OPERATOR_PAUSE
};

enum {
    CK_ACT_NONE = 0,
    CK_ACT_SET_FV,
    CK_ACT_DISABLE,
    CK_ACT_ENABLE
};

typedef struct {
    uint32_t Valid;
    uint32_t UsbOnline;
    uint32_t UsbType;
    uint32_t VoltageMv[2];
    uint32_t TempDeciK[2];
    uint32_t SocPct[2];
    uint32_t RemMah[2];
    uint32_t FullMah[2];
    int32_t  CurrentMa[2];
    uint32_t Flags[2];
} CK_TELEMETRY;

typedef struct {
    uint32_t State;
    uint32_t SafetyReason;
    uint32_t FvProgrammed;
    uint32_t Paused;
    uint32_t ConsecutiveGaugeErrs;
    uint32_t EnableCount;
    uint32_t DisableCount;
    uint32_t SafetyTrips;
    uint64_t GapUntilUs;
    uint64_t LastEnableAttemptUs;
    uint64_t LastSampleUs;
    CK_TELEMETRY LastGood;
} CK_POLICY;

void     CkPolicyInit(CK_POLICY *p);
void     CkPolicySetPaused(CK_POLICY *p, uint32_t paused);
uint32_t CkPolicyOnSample(CK_POLICY *p, const CK_TELEMETRY *t, uint64_t now_us);
uint32_t CkPolicyOnOpDone(CK_POLICY *p, uint32_t op_kind, uint32_t ok, uint64_t now_us);
uint32_t CkPolicyTick(CK_POLICY *p, uint64_t now_us);

#endif
