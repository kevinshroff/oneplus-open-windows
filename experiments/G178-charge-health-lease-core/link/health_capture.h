/* SPDX-License-Identifier: MIT
 * Pure validation of completed, immutable G167/G160 kernel-provider results.
 * The native adapter must obtain these through their fixed RESULT IOCTLs;
 * user-supplied sensor values are not an admissible producer.
 * These finite observations do not establish a production PnP/power lease.
 */
#ifndef OPEN_CHARGE_HEALTH_CAPTURE_H
#define OPEN_CHARGE_HEALTH_CAPTURE_H
#include <stdint.h>
#include <stddef.h>
#define CH_CONFIG_BYTES 1096u
#define CH_GAUGE_BYTES 279880u
#define CH_FRESH_100NS UINT64_C(50000000)
#define CH_PAIR_100NS UINT64_C(20000000)
enum {CH_OK,CH_ARGUMENT,CH_IDENTITY,CH_NONCE,CH_FRESHNESS,CH_CONFIG_RESULT,
 CH_CONFIG_TRACE,CH_GAUGE_RESULT,CH_GAUGE_TRACE,CH_GAUGE_DATA,
 CH_TEMPERATURE,CH_VOLTAGE,CH_CURRENT,CH_PROFILE,CH_STATE};
enum {CH_OBSERVE,CH_BEFORE_FV,CH_BEFORE_RESTART,CH_RENEW};
typedef struct {
 uint64_t Nonce,ConfigBegin100ns,ConfigEnd100ns,GaugeEnd100ns;
 uint32_t StateFirst,StateLast,Enable,FloatMv,FastMa,UsbType;
 uint32_t VoltageMv[2],TemperatureDeciK[2],CurrentRaw[2],Flags[2];
 uint32_t RemainingMah[2],FullMah[2],ChargePercent[2];
}CH_HEALTH;
uint32_t CHValidate(const uint8_t*config,size_t configBytes,
 const uint8_t*gauges,size_t gaugeBytes,uint64_t nonce,uint64_t now100ns,
 uint64_t previousNonce,uint64_t previousGaugeEnd100ns,uint32_t role,
 CH_HEALTH*out);
#endif
