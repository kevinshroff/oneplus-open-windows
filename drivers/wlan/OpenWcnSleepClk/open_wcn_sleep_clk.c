/* SPDX-License-Identifier: MIT
 * OpenWcnSleepClk — Enables PMK8550 GPIO3 (32.768 kHz sleep_clk, SPMI SID=0 PPID=0xBA)
 * for Qualcomm WCN7850 (FastConnect 7800) on OnePlus Open (SM8550 / Kalama).
 *
 * Without PMK8550 GPIO3 configured as func1 output (MODE_CTL=0x01, DIG_VIN_CTL=0x00,
 * DIG_PULL_CTL=0x05, DIG_OUT_SRC_CTL=0x02, DIG_OUT_DRV_CTL=0x03, EN_CTL=0x80),
 * WCN7850's AON sleep timer stays at 0 (SLP_TMR_VAL_HI=0, SLP_TMR_VAL_LO=0,
 * aon_pmm_sync_success=0) and firmware asserts at cmnos_thread_patch.c:1174
 * (BHI_ERRCODE=0xCAFECACE) ~2.4s after start.
 */
#include <ntddk.h>
#include <stdint.h>

#define SPMI_APID_MAP_PA   0x0C402000ULL
#define SPMI_APID_OWN_PA   0x0C42D000ULL
#define SPMI_CHNLS_PA      0x0C500000ULL
#define PMK8550_SID        0u
#define PMK8550_GPIO3_PPID 0xBAu
#define SPMI_EE_APSS       0u

static int SpmiWrite1(volatile uint32_t *ch, uint32_t off, uint8_t val) {
    ch[4] = (uint32_t)val;                           /* WDATA0 (+0x10) */
    ch[0] = 0x00000000u | ((off & 0xFFu) << 4) | 0u; /* EXT_WRITEL 1 byte */
    for (int i = 0; i < 200; i++) {
        uint32_t st = ch[2];                         /* STATUS (+0x08) */
        if (st & 1u) {
            return (st & 0xEu) ? -(int)(st & 0xEu) : 0;
        }
        KeStallExecutionProcessor(5);
    }
    return -1;
}

static void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = SPMI_APID_MAP_PA;
    volatile uint32_t *apid_map = (volatile uint32_t *)MmMapIoSpace(pa, 0x2000, MmNonCached);
    pa.QuadPart = SPMI_APID_OWN_PA;
    volatile uint32_t *apid_own = (volatile uint32_t *)MmMapIoSpace(pa, 0x2000, MmNonCached);

    uint32_t target_apid = 0xFFFFFFFFu;
    if (apid_map && apid_own) {
        for (uint32_t a = 0; a < 1024; a++) {
            uint32_t m = apid_map[a];
            if (((m >> 16) & 0xFu) == PMK8550_SID &&
                ((m >> 8) & 0xFFu) == PMK8550_GPIO3_PPID &&
                (apid_own[a] & 0xFFu) == SPMI_EE_APSS) {
                target_apid = a;
                break;
            }
        }
    }

    if (target_apid < 1024) {
        pa.QuadPart = SPMI_CHNLS_PA + (uint64_t)target_apid * 0x1000ULL;
        volatile uint32_t *wch = (volatile uint32_t *)MmMapIoSpace(pa, 0x1000, MmNonCached);
        if (wch) {
            SpmiWrite1(wch, 0x40, 0x01); /* MODE_CTL: OUTPUT */
            SpmiWrite1(wch, 0x41, 0x00); /* DIG_VIN_CTL: power-source 0 */
            SpmiWrite1(wch, 0x42, 0x05); /* DIG_PULL_CTL: NO_PULL */
            SpmiWrite1(wch, 0x44, 0x02); /* DIG_OUT_SRC_CTL: func1 (32.768 kHz sleep_clk) */
            SpmiWrite1(wch, 0x45, 0x03); /* DIG_OUT_DRV_CTL: high drive */
            SpmiWrite1(wch, 0x46, 0x80); /* EN_CTL: PERPH_EN = 1 */
            MmUnmapIoSpace((PVOID)wch, 0x1000);
        }
    }

    if (apid_own) MmUnmapIoSpace((PVOID)apid_own, 0x2000);
    if (apid_map) MmUnmapIoSpace((PVOID)apid_map, 0x2000);
    return STATUS_SUCCESS;
}
