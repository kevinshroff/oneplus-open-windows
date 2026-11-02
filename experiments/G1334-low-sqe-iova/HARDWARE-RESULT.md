# Low SQE address trial: same fatal start boundary

The signed, native-linked G1334 candidate ran once in the existing normal
Windows session with ordinary logging and no GPU instruction breakpoints.
The changed SQE base was read back as `0x00100000`, high word zero; the ring
retained the nonsecure64 address `0x4000000000`. The pre-release AHB/current
check returned success.

The last trace marker was `STORE_CALL_BEGIN stage3`. No corresponding return
or first CP fence followed, and the host subsequently enumerated Qualcomm
900E. This rejects the isolated low-SQE address candidate as a solution to the
recurring start failure. It does not recover the fault PC, prove store
retirement or exclude every GPU address/visibility/security issue. The G1334
live table graph was not separately captured.

One fresh Sahara mode2 handshake and one RESET7/ACK8 software recovery reset
completed. No programmer or storage-write command was sent. The existing debugger was reattached to the new WinPE kernel, its owned
initial stop was classified/resumed, and the WinPE control agent reconnected.
The actual offline SYSTEM control sets were fenced to Start4 with all three
GPU once options0, read back and unloaded. Existing Wi-Fi policies were
preserved. Recovery used no manual phone restart.

Do not repeat the consumed activation. Preserve the useful G1325 CPU graph
and content results, then select a different source-backed discriminator.
GPU command execution and Windows acceleration remain unfinished.
