/* SPDX-License-Identifier: MIT */
#ifndef G137_PROTOCOL_H
#define G137_PROTOCOL_H
#include "g137_capture.h"
#define G137_IOCTL_RETIRE CTL_CODE(FILE_DEVICE_UNKNOWN,0xa04,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#define G137_IOCTL_STATE CTL_CODE(FILE_DEVICE_UNKNOWN,0xa05,METHOD_BUFFERED,FILE_READ_ACCESS)
C_ASSERT(sizeof(G99_CAPTURE)==G137_CAPTURE_BYTES);
C_ASSERT(sizeof(G137_STATE)==64);
/* RETIRE input: original32-byte G99_REQUEST (Count/Reserved zero), followed
 * by the complete frozen139720-byte capture. Its output is G137_STATE64.
 * STATE input is the original zero-nonce/count32-byte request, output64.
 */
#define G137_RETIRE_BYTES (sizeof(G99_REQUEST)+sizeof(G99_CAPTURE))
#endif
