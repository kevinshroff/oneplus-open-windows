/* SPDX-License-Identifier: MIT
 * Fixed read-only requests: four original OEM queries plus matching published
 * property GETs. No notification enable, setter, control or caller selector.
 */
#ifndef G164_CODEC_H
#define G164_CODEC_H
#include <stdint.h>
#define G164_QUERY_COUNT 10u
#define G164_REPLY_LIMIT 1024u
typedef struct {uint32_t Opcode,Property,RequestBytes,ReplyBytes;}G164_QUERY;
typedef struct {
 uint32_t WireValidMask,ValueValidMask,ServiceRejectedMask;
 uint32_t VoltageMax,Reserved1,Reserved2,Reserved3,Reserved4,Reserved5;
 uint32_t BatteryState,RemainingCapacity,Rate,Voltage,PowerState,ChargingSource,TemperatureRaw,CurrentRaw;
 uint32_t OpenCircuitVoltage,VoltageNow,CurrentNow,TemperatureProperty,CapacityProperty,UsbOnline,UsbType,LegacyStatus;
 uint32_t ServiceResult[G164_QUERY_COUNT];
}G164_BATTERY;
const G164_QUERY*G164QuerySpec(uint32_t index);
uint32_t G164BuildQuery(uint32_t index,uint8_t out[24]);
int G164DecodeReply(uint32_t index,const uint8_t*data,uint32_t bytes,G164_BATTERY*out);
#endif
