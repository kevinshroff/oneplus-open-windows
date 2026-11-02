/* SPDX-License-Identifier: MIT
 * Fixed GETs, board FV and a bounded charge pulse. No raw value/property API.
 */
#ifndef CL_CODEC_H
#define CL_CODEC_H
#include <stdint.h>
#define CL_GET_COUNT 10u
#define CL_FV_QUERY 10u
#define CL_ENABLE_QUERY 11u
#define CL_DISABLE_QUERY 12u
#define CL_QUERY_COUNT 13u
#define CL_REPLY_LIMIT 1024u
typedef struct {uint32_t Opcode,Property,RequestBytes,ReplyBytes;}CL_QUERY;
typedef struct {
 uint32_t WireValidMask,ValueValidMask,ServiceRejectedMask;
 uint32_t VoltageMax,ControlAckMask,Reserved2,Reserved3,Reserved4,Reserved5;
 uint32_t BatteryState,RemainingCapacity,Rate,Voltage,PowerState,ChargingSource,TemperatureRaw,CurrentRaw;
 uint32_t OpenCircuitVoltage,VoltageNow,CurrentNow,TemperatureProperty,CapacityProperty,UsbOnline,UsbType,LegacyBatteryId;
 uint32_t ServiceResult[CL_QUERY_COUNT];
}CL_BATTERY;
const CL_QUERY*CLQuerySpec(uint32_t index);
uint32_t CLBuildQuery(uint32_t index,uint8_t out[24]);
int CLDecodeReply(uint32_t index,const uint8_t*data,uint32_t bytes,CL_BATTERY*out);
#endif
