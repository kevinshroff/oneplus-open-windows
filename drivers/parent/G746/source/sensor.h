/* Fixed physical acquisition under the caller's live PnP resource/D0 lifetime.
 * No mapping, charging setters, gauge configuration, or user injection API. */
#ifndef OPEN_SENSOR_183_H
#define OPEN_SENSOR_183_H
#include <stdint.h>
#include "g104_core.h"
#include "g111_core.h"
#define S183_PAIR_100NS UINT64_C(20000000)
#define S183_TTL_100NS UINT64_C(300000000)
enum {S183_OK,S183_ARGUMENT,S183_CANCELLED,S183_CONFIG,S183_GAUGE,S183_POLICY,S183_TIME,S183_DATA};
typedef struct {
 void *Context;
 int (*Read)(void *,uint32_t,uint32_t *);
 int (*Write)(void *,uint32_t,uint32_t);
 int (*Available)(void *);
 uint64_t (*NowUs)(void *);
 uint64_t (*Now100ns)(void *);
 void (*DelayUs)(void *,uint32_t);
 void (*WaitInterval)(void *);
} S183_IO;
typedef struct {
 uint32_t Size,Version,Code,Uncertain;
 uint64_t Epoch,Sequence,Begin100ns,ConfigEnd100ns,GaugeEnd100ns,End100ns;
 uint32_t ConfigNativeReads,ConfigNativeWrites,ConfigGuard;
 uint32_t GaugeNativeReads,GaugeNativeWrites,GaugeGuard;
 uint32_t PolicyCommands,PolicyCompleted,PolicyFault,CancelledClean;
 G111_RESULT Config;
 G104_RESULT Gauge;
} S183_RESULT;
typedef struct {
 uint32_t VoltageMv[2],TemperatureDeciK[2],CurrentRaw[2],Flags[2];
 uint32_t RemainingMah[2],FullMah[2],Percent[2];
 uint32_t ChargerStateFirst,ChargerStateLast,Enable,FloatMv,FastMa,UsbType,Mode;
} S183_READING;
void S183Capture(const S183_IO *,uint64_t epoch,uint64_t sequence,S183_RESULT *);
/* Structural/identity/trace validation only; not charge-policy admission. */
uint32_t S183Validate(const S183_RESULT *,S183_READING *);
#endif
