/* SPDX-License-Identifier: MIT
 * Fixed read-only requests: four original OEM queries plus matching published
 * property GETs. No notification enable, setter, control or caller selector.
 */
#ifndef G159_CODEC_H
#define G159_CODEC_H
#include <stdint.h>
#define G159_QUERY_COUNT 10u
#define G159_REPLY_LIMIT 1024u
typedef struct {uint32_t Opcode,Property,RequestBytes,ReplyBytes;}G159_QUERY;
typedef struct {
 uint32_t WireValidMask,ValueValidMask,ServiceRejectedMask;
 uint32_t PowerUnit,DesignCapacity,LastFullCapacity,DesignVoltage,CycleCount,BatteryId;
 uint32_t BatteryState,RemainingCapacity,Rate,Voltage,PowerState,ChargingSource,TemperatureRaw,CurrentRaw;
 uint32_t OpenCircuitVoltage,VoltageNow,CurrentNow,TemperatureProperty,CapacityProperty,UsbOnline,UsbType,LegacyStatus;
 uint32_t ServiceResult[G159_QUERY_COUNT];
}G159_BATTERY;
const G159_QUERY*G159QuerySpec(uint32_t index);
uint32_t G159BuildQuery(uint32_t index,uint8_t out[24]);
int G159DecodeReply(uint32_t index,const uint8_t*data,uint32_t bytes,G159_BATTERY*out);
#endif
