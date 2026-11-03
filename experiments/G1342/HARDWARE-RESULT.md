# G1342 hardware result

The bounded native CE3 getter completed successfully: two accepted reads, HP=20 and TP=20, with no retry. A subsequent CPU-only snapshot found local HP, cached TP and DMA RRI TP all equal to20. All15 spans matched between the two CPU passes. The task returned Ready with result0, and the CPU capture resumed the target successfully.

The source ring contains32 entries of4 DWORDs, or128 DWORDs. Hardware/SRNG indices use DWORD units; software wrapper read/write slots use entry units. Wrapper slots5/5 therefore correspond to20/20 DWORDs. The reap cursor16 is one entry behind the next completion: `(16 + 4) % 128 = 20`. Comparing16 directly with TP20 would incorrectly imply an outstanding entry. All32 ownership-context QWORDs were zero; the HAL error counter was zero.

Endpoint2 had queue7 and credits0 in both CPU passes. Together with the drained source-ring indices and empty ownership contexts, this is a credit-blocked snapshot without an observed persistent CE3 source backlog. It shifts attention toward credit return and the command/reply path beyond source-ring delivery. It does not identify why credits were not returned.

Hardware and CPU samples were sequential, not atomic. The native queries use the existing driver wake, lock and window-selection protocol; they are active observations. The later CPU capture performs no MMIO. These observations support source descriptor consumption; they do not prove correct device-visible payload bytes, target WMI command execution, absence of every coherency fault, or dead firmware. Zero ownership contexts are metadata observations; no packet pointers were dereferenced.

This epoch used one successful initialization with NeedReboot=false and no explicit scan, cached-network query, connect, statistics or extra diagnostic API call from that initializer. The getter itself made only its two selected native reads. No repair or connectivity success is claimed.

The independent recount decoded both100-byte getter outputs, compared all15 raw CPU spans, counted all32 ownership-context values and checked the index-unit conversion. See [machine-readable sanitized result](HARDWARE-RESULT.json). Private identity, addresses and raw traces are omitted.
