/* Minimal fields consumed by the actual G456 body. */
typedef struct {ULONGLONG RunId;} OGO_CONTEXT;
typedef struct {
 int Cancelled,Poisoned,Closed;ULONGLONG Generation;void *Io;
 struct {void *Cookie;} Owner;
 struct {ULONG phase;struct {void *cookie;int (*barrier)(void *,int);} ops;} Core;
 g196_preflight Inputs;
} G321_RUNTIME;
typedef struct G433_RUNTIME {
 int Cancelled;struct {int held,released,poisoned;} Power;G321_RUNTIME *Gmu;
 struct {G456_FACTS Board;NTSTATUS (*ReadGpuRegister)(void *,ULONG,PULONG);
  NTSTATUS (*WriteGpuRegister)(void *,ULONG,ULONG);NTSTATUS (*AhbFenceStatus)(void *,PULONG);} Gpu;
 ULONGLONG Generation;G456_REPORT Hwinit;
} G433_RUNTIME;
NTSTATUS OgoCpCurrent(OGO_CONTEXT *);
NTSTATUS G482CoreRead(void *,ULONG,PULONG);
NTSTATUS G482CoreWrite(void *,ULONG,ULONG);
ULONG KeGetCurrentIrql(void);
ULONG DbgPrintEx(ULONG,ULONG,const char *,...);
NTSTATUS G456ConfigureGpuStopped(struct G433_RUNTIME *);
