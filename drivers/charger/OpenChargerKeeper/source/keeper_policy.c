/* SPDX-License-Identifier: MIT
 * Always-on battery charging & safety watchdog policy for OnePlus Open (SM8550).
 */
#include "keeper_policy.h"

static uint32_t MaxU32(uint32_t a, uint32_t b){ return a > b ? a : b; }
static uint32_t MinU32(uint32_t a, uint32_t b){ return a < b ? a : b; }
static uint32_t AbsDiff(uint32_t a, uint32_t b){ return a > b ? (a - b) : (b - a); }

void CkPolicyInit(CK_POLICY *p){
    if(!p) return;
    uint8_t *b = (uint8_t*)p;
    for(uint32_t i=0;i<sizeof(*p);i++) b[i]=0;
    p->State = CK_ST_IDLE;
    p->SafetyReason = CK_SAFE_OK;
}

void CkPolicySetPaused(CK_POLICY *p, uint32_t paused){
    if(!p) return;
    p->Paused = paused ? 1u : 0u;
    if(p->Paused){
        p->SafetyReason = CK_SAFE_OPERATOR_PAUSE;
    } else if(p->State == CK_ST_PAUSED){
        p->State = CK_ST_IDLE;
        p->SafetyReason = CK_SAFE_OK;
    }
}

static uint32_t EvalSafety(const CK_TELEMETRY *t, uint32_t recovering_temp){
    if(!t->UsbOnline) return CK_SAFE_NO_USB;
    uint32_t tmin = recovering_temp ? CK_TEMP_REC_MIN_DK : CK_TEMP_MIN_DK;
    uint32_t tmax = recovering_temp ? CK_TEMP_REC_MAX_DK : CK_TEMP_MAX_DK;
    for(uint32_t i=0;i<2;i++){
        if(t->TempDeciK[i] < tmin || t->TempDeciK[i] > tmax) return CK_SAFE_TEMP;
        if(t->VoltageMv[i] > CK_VOLT_HARD_MAX_MV || t->VoltageMv[i] < 2800u) return CK_SAFE_OVERVOLT;
    }
    if(AbsDiff(t->VoltageMv[0], t->VoltageMv[1]) > CK_VOLT_IMBAL_MV) return CK_SAFE_IMBALANCE;
    return CK_SAFE_OK;
}

static uint32_t TriggerDisable(CK_POLICY *p, uint32_t reason){
    uint32_t was_active = (p->State == CK_ST_CHARGING || p->State == CK_ST_ENABLING ||
                           p->State == CK_ST_GAP_WAIT || p->State == CK_ST_PRE_OFF);
    p->SafetyReason = reason;
    if(reason != CK_SAFE_OK && reason != CK_SAFE_NO_USB && reason != CK_SAFE_OPERATOR_PAUSE){
        if(p->State != CK_ST_SAFETY_HOLD) p->SafetyTrips++;
    }
    if(was_active){
        p->State = CK_ST_DISABLING;
        return CK_ACT_DISABLE;
    }
    if(reason == CK_SAFE_OPERATOR_PAUSE) p->State = CK_ST_PAUSED;
    else if(reason == CK_SAFE_NO_USB) p->State = CK_ST_IDLE;
    else p->State = CK_ST_SAFETY_HOLD;
    return CK_ACT_NONE;
}

uint32_t CkPolicyOnSample(CK_POLICY *p, const CK_TELEMETRY *t, uint64_t now_us){
    if(!p || !t) return CK_ACT_NONE;
    p->LastSampleUs = now_us;

    if(p->Paused) return TriggerDisable(p, CK_SAFE_OPERATOR_PAUSE);

    if(!t->Valid){
        p->ConsecutiveGaugeErrs++;
        if(p->ConsecutiveGaugeErrs >= CK_MAX_GAUGE_ERRS){
            return TriggerDisable(p, CK_SAFE_GAUGE_ERR);
        }
        return CK_ACT_NONE;
    }
    p->ConsecutiveGaugeErrs = 0;
    p->LastGood = *t;

    uint32_t recovering_temp = (p->State == CK_ST_SAFETY_HOLD && p->SafetyReason == CK_SAFE_TEMP) ? 1u : 0u;
    uint32_t safe = EvalSafety(t, recovering_temp);
    if(safe != CK_SAFE_OK){
        return TriggerDisable(p, safe);
    }

    /* Safe & USB online */
    if(p->State == CK_ST_SAFETY_HOLD){
        p->State = CK_ST_IDLE;
        p->SafetyReason = CK_SAFE_OK;
    } else {
        p->SafetyReason = CK_SAFE_OK;
    }

    uint32_t max_soc = MaxU32(t->SocPct[0], t->SocPct[1]);
    uint32_t min_soc = MinU32(t->SocPct[0], t->SocPct[1]);
    uint32_t max_v   = MaxU32(t->VoltageMv[0], t->VoltageMv[1]);

    /* Already in flight on a GLINK command? Don't interrupt it. */
    if(p->State == CK_ST_SET_FV || p->State == CK_ST_PRE_OFF ||
       p->State == CK_ST_GAP_WAIT || p->State == CK_ST_ENABLING ||
       p->State == CK_ST_DISABLING){
        return CK_ACT_NONE;
    }

    if(p->State == CK_ST_CHARGING){
        if(max_soc >= CK_SOC_STOP_PCT || max_v >= CK_VOLT_STOP_MV){
            p->State = CK_ST_DISABLING;
            return CK_ACT_DISABLE;
        }
        return CK_ACT_NONE;
    }

    if(p->State == CK_ST_HOLD_FULL){
        if(max_soc <= CK_SOC_START_PCT && max_v <= CK_VOLT_START_MV){
            p->State = CK_ST_IDLE;
        } else {
            return CK_ACT_NONE;
        }
    }

    /* CK_ST_IDLE: decide whether to start charging */
    if(max_soc >= CK_SOC_STOP_PCT || max_v >= CK_VOLT_STOP_MV){
        p->State = CK_ST_HOLD_FULL;
        return CK_ACT_NONE;
    }
    if((min_soc <= CK_SOC_START_PCT || max_v <= CK_VOLT_START_MV) &&
       (p->LastEnableAttemptUs == 0 || now_us - p->LastEnableAttemptUs >= CK_RETRY_COOLDOWN_US)){
        p->LastEnableAttemptUs = now_us;
        if(!p->FvProgrammed){
            p->State = CK_ST_SET_FV;
            return CK_ACT_SET_FV;
        }
        p->State = CK_ST_PRE_OFF;
        return CK_ACT_DISABLE;
    }
    return CK_ACT_NONE;
}

uint32_t CkPolicyOnOpDone(CK_POLICY *p, uint32_t op_kind, uint32_t ok, uint64_t now_us){
    if(!p) return CK_ACT_NONE;
    (void)op_kind;
    if(!ok){
        /* Command failed/timed out: fall back safely to IDLE/HOLD */
        if(p->State == CK_ST_DISABLING){
            p->State = p->Paused ? CK_ST_PAUSED :
                       (p->SafetyReason != CK_SAFE_OK && p->SafetyReason != CK_SAFE_NO_USB) ? CK_ST_SAFETY_HOLD : CK_ST_IDLE;
        } else {
            p->State = CK_ST_IDLE;
        }
        return CK_ACT_NONE;
    }
    switch(p->State){
    case CK_ST_SET_FV:
        p->FvProgrammed = 1u;
        p->State = CK_ST_PRE_OFF;
        return CK_ACT_DISABLE;
    case CK_ST_PRE_OFF:
        p->DisableCount++;
        p->GapUntilUs = now_us + CK_RESTART_GAP_US;
        p->State = CK_ST_GAP_WAIT;
        return CK_ACT_NONE;
    case CK_ST_ENABLING:
        p->EnableCount++;
        p->State = CK_ST_CHARGING;
        return CK_ACT_NONE;
    case CK_ST_DISABLING:
        p->DisableCount++;
        if(p->Paused) p->State = CK_ST_PAUSED;
        else if(p->SafetyReason == CK_SAFE_NO_USB) p->State = CK_ST_IDLE;
        else if(p->SafetyReason != CK_SAFE_OK) p->State = CK_ST_SAFETY_HOLD;
        else p->State = CK_ST_HOLD_FULL;
        return CK_ACT_NONE;
    default:
        return CK_ACT_NONE;
    }
}

uint32_t CkPolicyTick(CK_POLICY *p, uint64_t now_us){
    if(!p) return CK_ACT_NONE;
    if(p->State == CK_ST_GAP_WAIT && now_us >= p->GapUntilUs){
        if(p->Paused){
            p->State = CK_ST_PAUSED;
            return CK_ACT_NONE;
        }
        p->State = CK_ST_ENABLING;
        return CK_ACT_ENABLE;
    }
    return CK_ACT_NONE;
}
