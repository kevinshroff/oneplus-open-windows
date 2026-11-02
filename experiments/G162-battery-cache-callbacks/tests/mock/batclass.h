/* Public subset for host tests; layouts compared with the actual ARM64 WDK. */
#ifndef G162_MOCK_BATCLASS_H
#define G162_MOCK_BATCLASS_H
#include "ntddk.h"
typedef enum { BatteryInformation, BatteryGranularityInformation, BatteryTemperature,
 BatteryEstimatedTime, BatteryDeviceName, BatteryManufactureDate,
 BatteryManufactureName, BatteryUniqueID, BatterySerialNumber } BATTERY_QUERY_INFORMATION_LEVEL;
typedef enum { BatteryCriticalBias, BatteryCharge, BatteryDischarge,
 BatteryChargingSource, BatteryChargerId, BatteryChargerStatus,
 BatteryChargerStatusNotify, BatteryChargingStatus } BATTERY_SET_INFORMATION_LEVEL;
typedef struct { ULONG PowerState,Capacity,Voltage; LONG Rate; } BATTERY_STATUS,*PBATTERY_STATUS;
typedef struct { ULONG Capabilities; uint8_t Technology,Reserved[3],Chemistry[4];
 ULONG DesignedCapacity,FullChargedCapacity,DefaultAlert1,DefaultAlert2,CriticalBias,CycleCount;
} BATTERY_INFORMATION;
typedef struct { ULONG PowerState,LowCapacity,HighCapacity; } BATTERY_NOTIFY,*PBATTERY_NOTIFY;
typedef struct {
 uint16_t MajorVersion,MinorVersion; PVOID Context;
 NTSTATUS (*QueryTag)(PVOID,PULONG);
 NTSTATUS (*QueryInformation)(PVOID,ULONG,BATTERY_QUERY_INFORMATION_LEVEL,LONG,PVOID,ULONG,PULONG);
 NTSTATUS (*SetInformation)(PVOID,ULONG,BATTERY_SET_INFORMATION_LEVEL,PVOID);
 NTSTATUS (*QueryStatus)(PVOID,ULONG,PBATTERY_STATUS);
 NTSTATUS (*SetStatusNotify)(PVOID,ULONG,PBATTERY_NOTIFY);
 NTSTATUS (*DisableStatusNotify)(PVOID);
 PVOID Pdo; PVOID DeviceName;
} BATTERY_MINIPORT_INFO;
#define BATTERY_CLASS_MAJOR_VERSION 1
#define BATTERY_CLASS_MINOR_VERSION 0
#define BATTERY_TAG_INVALID 0u
#define BATTERY_SYSTEM_BATTERY 0x80000000u
#define BATTERY_CAPACITY_RELATIVE 0x40000000u
#define BATTERY_UNKNOWN_CAPACITY 0xffffffffu
#define BATTERY_UNKNOWN_TIME 0xffffffffu
#define BATTERY_UNKNOWN_RATE 0x80000000u
#endif
