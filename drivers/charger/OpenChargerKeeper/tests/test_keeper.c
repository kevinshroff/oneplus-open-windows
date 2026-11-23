/* SPDX-License-Identifier: MIT
 * Host unit tests for OpenChargerKeeper policy & GLINK codec (ASan/UBSan).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../source/keeper_policy.h"
#include "../source/charger_codec.h"
#include "../source/glink_core.h"

static CK_TELEMETRY MakeGood(uint32_t soc0, uint32_t soc1, uint32_t v0, uint32_t v1, uint32_t t0, uint32_t t1, uint32_t usb){
    CK_TELEMETRY t;
    memset(&t, 0, sizeof(t));
    t.Valid = 1; t.UsbOnline = usb; t.UsbType = 1; /* SDP allowed! */
    t.SocPct[0] = soc0; t.SocPct[1] = soc1;
    t.VoltageMv[0] = v0; t.VoltageMv[1] = v1;
    t.TempDeciK[0] = t0; t.TempDeciK[1] = t1;
    t.RemMah[0] = 1000; t.FullMah[0] = 2400;
    t.RemMah[1] = 1000; t.FullMah[1] = 2400;
    return t;
}

static void TestHysteresisAndGap(void){
    CK_POLICY p; CkPolicyInit(&p);
    uint64_t now = 1000000ULL;

    /* 1. Low battery on SDP USB -> must SET_FV -> DISABLE -> 5s gap -> ENABLE */
    CK_TELEMETRY t = MakeGood(40, 42, 3700, 3710, 3050, 3060, 1);
    assert(CkPolicyOnSample(&p, &t, now) == CK_ACT_SET_FV);
    assert(p.State == CK_ST_SET_FV);

    assert(CkPolicyOnOpDone(&p, CK_OP_SET_FV, 1, now + 1000) == CK_ACT_DISABLE);
    assert(p.FvProgrammed == 1 && p.State == CK_ST_PRE_OFF);

    assert(CkPolicyOnOpDone(&p, CK_OP_DISABLE, 1, now + 2000) == CK_ACT_NONE);
    assert(p.State == CK_ST_GAP_WAIT);

    /* Before 5s gap expires -> no action */
    assert(CkPolicyTick(&p, now + 2000 + CK_RESTART_GAP_US - 1) == CK_ACT_NONE);
    /* At 5s gap -> ENABLE */
    assert(CkPolicyTick(&p, now + 2000 + CK_RESTART_GAP_US) == CK_ACT_ENABLE);
    assert(p.State == CK_ST_ENABLING);
    assert(CkPolicyOnOpDone(&p, CK_OP_ENABLE, 1, now + 6000000) == CK_ACT_NONE);
    assert(p.State == CK_ST_CHARGING && p.EnableCount == 1);

    /* 2. Mid-charge at 80% / 4.20V -> keeps charging */
    t = MakeGood(80, 80, 4200, 4210, 3080, 3090, 1);
    assert(CkPolicyOnSample(&p, &t, now + 20000000) == CK_ACT_NONE);
    assert(p.State == CK_ST_CHARGING);

    /* 3. Hits 85% -> disables and enters HOLD_FULL */
    t = MakeGood(85, 84, 4250, 4240, 3080, 3090, 1);
    assert(CkPolicyOnSample(&p, &t, now + 30000000) == CK_ACT_DISABLE);
    assert(p.State == CK_ST_DISABLING);
    assert(CkPolicyOnOpDone(&p, CK_OP_DISABLE, 1, now + 30001000) == CK_ACT_NONE);
    assert(p.State == CK_ST_HOLD_FULL);

    /* 4. Drops to 78% -> stays in HOLD_FULL */
    t = MakeGood(78, 78, 4120, 4120, 3050, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 60000000) == CK_ACT_NONE);
    assert(p.State == CK_ST_HOLD_FULL);

    /* 5. Drops to 75% and <=4150 mV -> resumes charging (FV already programmed, skips SET_FV!) */
    t = MakeGood(75, 74, 4100, 4100, 3050, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 90000000) == CK_ACT_DISABLE);
    assert(p.State == CK_ST_PRE_OFF);
}

static void TestSafetyCutoffs(void){
    CK_POLICY p; CkPolicyInit(&p);
    p.FvProgrammed = 1; p.State = CK_ST_CHARGING;
    uint64_t now = 100000000ULL;

    /* Over-temp > 43.0 C (3162 dK) -> immediate disable */
    CK_TELEMETRY t = MakeGood(50, 50, 3800, 3800, 3162, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now) == CK_ACT_DISABLE);
    assert(p.SafetyReason == CK_SAFE_TEMP && p.SafetyTrips == 1);
    CkPolicyOnOpDone(&p, CK_OP_DISABLE, 1, now + 1000);
    assert(p.State == CK_ST_SAFETY_HOLD);

    /* Still 40.5 C (3136 dK) -> stays in SAFETY_HOLD until <= 39.0 C (3121 dK) */
    t = MakeGood(50, 50, 3800, 3800, 3136, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 10000000) == CK_ACT_NONE);
    assert(p.State == CK_ST_SAFETY_HOLD);

    /* Cools to 38.0 C (3111 dK) -> recovers and restarts charging */
    t = MakeGood(50, 50, 3800, 3800, 3111, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 50000000) == CK_ACT_DISABLE);
    assert(p.State == CK_ST_PRE_OFF && p.SafetyReason == CK_SAFE_OK);

    /* Overvoltage > 4450 mV -> immediate disable */
    p.State = CK_ST_CHARGING;
    t = MakeGood(70, 70, 4460, 4450, 3050, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 60000000) == CK_ACT_DISABLE);
    assert(p.SafetyReason == CK_SAFE_OVERVOLT);

    /* Cell imbalance > 300 mV -> immediate disable */
    p.State = CK_ST_CHARGING;
    t = MakeGood(50, 50, 4050, 3700, 3050, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, now + 70000000) == CK_ACT_DISABLE);
    assert(p.SafetyReason == CK_SAFE_IMBALANCE);

    /* 3 consecutive invalid gauge reads -> immediate disable */
    p.State = CK_ST_CHARGING;
    CK_TELEMETRY bad; memset(&bad, 0, sizeof(bad));
    assert(CkPolicyOnSample(&p, &bad, now + 80000000) == CK_ACT_NONE);
    assert(CkPolicyOnSample(&p, &bad, now + 90000000) == CK_ACT_NONE);
    assert(CkPolicyOnSample(&p, &bad, now + 100000000) == CK_ACT_DISABLE);
    assert(p.SafetyReason == CK_SAFE_GAUGE_ERR);

    /* USB unplug -> disable cleanly without incrementing SafetyTrips */
    uint32_t trips_before = p.SafetyTrips;
    p.State = CK_ST_CHARGING;
    t = MakeGood(50, 50, 3800, 3800, 3050, 3050, 0);
    assert(CkPolicyOnSample(&p, &t, now + 110000000) == CK_ACT_DISABLE);
    assert(p.SafetyReason == CK_SAFE_NO_USB && p.SafetyTrips == trips_before);
}

static void TestCodecAndPause(void){
    uint8_t buf[24];
    assert(CLBuildQuery(CL_FV_QUERY, buf) == 24);
    assert(buf[20] == (4470 & 0xFF) && buf[21] == ((4470 >> 8) & 0xFF));
    assert(CLBuildQuery(CL_ENABLE_QUERY, buf) == 24);
    assert(buf[16] == 24 && buf[20] == 1);
    assert(CLBuildQuery(CL_RESTART_OFF_QUERY, buf) == 24);
    assert(buf[16] == 24 && buf[20] == 0);

    CK_POLICY p; CkPolicyInit(&p); p.State = CK_ST_CHARGING;
    CkPolicySetPaused(&p, 1);
    CK_TELEMETRY t = MakeGood(50, 50, 3800, 3800, 3050, 3050, 1);
    assert(CkPolicyOnSample(&p, &t, 1000) == CK_ACT_DISABLE);
    CkPolicyOnOpDone(&p, CK_OP_DISABLE, 1, 2000);
    assert(p.State == CK_ST_PAUSED);
    CkPolicySetPaused(&p, 0);
    assert(p.State == CK_ST_IDLE);
}

int main(void){
    TestHysteresisAndGap();
    TestSafetyCutoffs();
    TestCodecAndPause();
    printf("ALL OpenChargerKeeper POLICY + CODEC TESTS PASSED\n");
    return 0;
}
