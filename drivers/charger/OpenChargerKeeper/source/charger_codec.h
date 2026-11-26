/* SPDX-License-Identifier: MIT
 * Fixed GETs, board FV and a bounded charge pulse. No raw value/property API.
 */
#ifndef CL_CODEC_H
#define CL_CODEC_H
#include <stdint.h>
#define CL_GET_COUNT 14u
#define CL_CORE_GET_MASK 0x3FFu  /* GETs 0..9: a rejection fails the sample */
#define CL_USB_GET_FIRST 10u     /* GETs 10..13: optional USB input telemetry (opcode 0x32) */
#define CL_FV_QUERY 14u
#define CL_ICL_QUERY 15u         /* optional USB_PROPERTY_SET prop 5 (3A input current limit) */
#define CL_ENABLE_QUERY 16u
#define CL_DISABLE_QUERY 17u
#define CL_RESTART_OFF_QUERY 18u
#define CL_QUERY_COUNT 19u
#define CL_REPLY_LIMIT 1024u
typedef struct {uint32_t Opcode,Property,RequestBytes,ReplyBytes;}CL_QUERY;
typedef struct {
 uint32_t WireValidMask,ValueValidMask,ServiceRejectedMask;
 uint32_t VoltageMax,ControlAckMask,UsbVoltNow,UsbCurrNow,UsbCurrMax,UsbInputLimit; /* USB: uV / uA */
 uint32_t BatteryState,RemainingCapacity,Rate,Voltage,PowerState,ChargingSource,TemperatureRaw,CurrentRaw;
 uint32_t OpenCircuitVoltage,VoltageNow,CurrentNow,TemperatureProperty,CapacityProperty,UsbOnline,UsbType,LegacyBatteryId;
 uint32_t ServiceResult[CL_QUERY_COUNT];
}CL_BATTERY;
const CL_QUERY*CLQuerySpec(uint32_t index);
uint32_t CLBuildQuery(uint32_t index,uint8_t out[24]);
int CLDecodeReply(uint32_t index,const uint8_t*data,uint32_t bytes,CL_BATTERY*out);
#endif
