/* Scalar host stand-ins only; no Windows ABI/hardware claim. */
#include <stdint.h>
#include <stddef.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t NTSTATUS;
typedef unsigned char BOOLEAN;typedef ULONG *PULONG;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_NOT_SUPPORTED (-2)
#define STATUS_BUFFER_OVERFLOW (-3)
#define STATUS_DEVICE_NOT_READY (-4)
#define STATUS_DEVICE_POWER_FAILURE (-5)
#define STATUS_DEVICE_DATA_ERROR (-6)
#define STATUS_DEVICE_BUSY (-7)
#define STATUS_ACCESS_DENIED (-8)
#define MAXULONG UINT32_MAX
#define PASSIVE_LEVEL 0
#define DPFLTR_IHVVIDEO_ID 1
#define DPFLTR_INFO_LEVEL 2
#define RTL_NUMBER_OF(x) (sizeof(x)/sizeof((x)[0]))
#define G190_STARTUP_COMPLETE 11
#define G190_COMPLETE 2
typedef struct {ULONG soc_id,revision,source_sku;} g196_preflight;
