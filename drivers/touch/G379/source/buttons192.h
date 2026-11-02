/* SPDX-License-Identifier: MIT. Portable offline decoder; no MMIO or OS API. */
#ifndef OPEN_BUTTONS_192_H
#define OPEN_BUTTONS_192_H
#include <stddef.h>
#include <stdint.h>
#define B192_CAPTURE_BYTES 139720u
#define B192_MAX_SAMPLES 1024u
#define B192_DEBOUNCE_US UINT64_C(15000)
#define B192_MAX_GAP_US UINT64_C(100000)
enum { B192_OK,B192_ARGUMENT,B192_ABI,B192_PLATFORM,B192_NONCE,B192_RESULT,
 B192_IDENTITY,B192_CONFIG,B192_TRACE,B192_CLOCK,B192_SEQUENCE,B192_HELD_START,
 B192_GAP,B192_STOPPED };
enum { B192_POWER=1u,B192_VOLUME_UP=2u,B192_VOLUME_DOWN=4u };
typedef struct {uint64_t AtUs;uint8_t Raw[3],Reserved[5];} B192_SAMPLE;
typedef struct {
 uint32_t Samples,Requested;uint64_t BeginUs,EndUs;
 B192_SAMPLE Sample[B192_MAX_SAMPLES];
} B192_CAPTURE;
/* Validates the exact original G99/G100 ABI, including every command's fixed
 * order/data binding. Does not establish current ownership or physical labels. */
uint32_t B192ValidateCapture(const uint8_t*,size_t,uint64_t,B192_CAPTURE*);
uint32_t B192Levels(const uint8_t raw[3]);
typedef struct {
 uint64_t Epoch,LastSequence,LastUs,CandidateAt[3];
 uint32_t Stable,Candidate,Started,Fault,Stopped;
} B192_STREAM;
typedef struct {
 uint64_t Sequence,AtUs;
 uint32_t Levels,Down,Up,ReportCount;
 uint8_t Report[2][2]; /* {report ID, one-byte bitmap}; not a delivery ACK */
} B192_EVENT;
void B192StreamInit(B192_STREAM*,uint64_t epoch);
/* 15ms software stability/100ms maximum gap are candidate D0 policy choices,
 * not a reconstruction of PON electrical debounce or proof of native cadence.
 * The first sample must be all-released. All failures latch until a NEW epoch
 * is initialized by the eventual trusted owner. No native adapter exists. */
uint32_t B192StreamStep(B192_STREAM*,uint64_t epoch,uint64_t sequence,const B192_SAMPLE*,B192_EVENT*);
/* Produces logical release reports for a later adapter to submit and verify;
 * never claims that the host accepted them or the physical key was released. */
void B192StreamStop(B192_STREAM*,B192_EVENT*);
extern const uint8_t B192Descriptor[];
extern const uint32_t B192DescriptorBytes;
/* No current mapping/resource/power/VHF qualification may be upgraded by user
 * flags or registry. This slice has no native hooks and stays closed. */
int B192NativeAdmission(void);
#endif
