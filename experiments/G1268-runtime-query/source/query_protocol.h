#ifndef G1268_PROTOCOL_H
#define G1268_PROTOCOL_H
typedef unsigned int G1268_U32;
typedef unsigned long long G1268_U64;
#define G1268_VERSION 1u
#define G1268_MAGIC 0x38365147u /* GQ68 */
#define G1268_QUERY_TAG 0x38363231u
#define G1268_IOCTL_STATUS ((0x22u<<16)|(1u<<14)|(0xa20u<<2))
#define G1268_IOCTL_QUERY_ONCE ((0x22u<<16)|(3u<<14)|(0xa21u<<2))
enum {G1268_IDLE=0,G1268_QUEUED=1,G1268_EXECUTING=2,G1268_COMPLETE=3,G1268_ERROR=4,G1268_INCOMPLETE_RETAINED=5};
enum {G1268_CAP_UNKNOWN=0,G1268_CAP_UNAVAILABLE=1,G1268_CAP_AVAILABLE=2};
enum {G1268_F_ACCEPTED=1,G1268_F_THUNK_ENTERED=2,G1268_F_THUNK_RETURNED=4,G1268_F_COMPLETION=8,G1268_F_BUSY=16,G1268_F_UNSUPPORTED=32,G1268_F_RETAINED=64};
typedef struct {G1268_U32 Version,Tag;} G1268_QUERY_REQUEST;
typedef struct {G1268_U64 X[8];G1268_U64 Entries,Returns,Interrupted;} G1268_MONITOR_FRAME;
typedef struct {
 G1268_U32 Magic,Version,Bytes,State,Flags,Availability,QueriesAccepted,Reserved;
 G1268_U64 Input[8];
 G1268_MONITOR_FRAME Monitor;
} G1268_REPORT;
/* Every public request is fixed-profile; there is no caller FID/argument field. */
int G1268Accept(G1268_REPORT *R);
int G1268Begin(G1268_REPORT *R);
void G1268Finish(G1268_REPORT *R,const G1268_MONITOR_FRAME *M);
void G1268Initialize(G1268_REPORT *R);
#endif
