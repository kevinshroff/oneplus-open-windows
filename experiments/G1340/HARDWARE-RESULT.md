# Hardware result: Boot172

The bounded in-driver getter worked: all four native CE2 register queries returned accepted data, and all four values matched the later stable CPU snapshot. Wi-Fi remained unconnected, with EP2 credits exhausted and queued commands. This is a working diagnostic route, not a Wi-Fi fix.

One initialization returned success with `NeedReboot=false`; WLAN remained Running with Start=4. The task requested zero explicit scans, but the trace contains OS-originated scan activity. The loaded getter body and the retained noncached-allocation instruction matched the reviewed candidate. Actual DMA mapping cache attributes were not measured.

| CE2 index (DWORD units) | Native hardware | Later CPU local | CPU cached remote | RAM RRI shadow |
| --- | ---: | ---: | ---: | ---: |
| Status HP / TP | 132 / 132 | TP 132 | HP 132 | HP 132 |
| Destination HP / TP | 62 / 66 | HP 62 | TP 66 | TP 66 |

The queries ran in order status HP, status TP, destination HP, destination TP. Each returned API success, 100 bytes and one output DWORD. The later CPU capture contained 29 unchanged before/after spans; its measured pause upper bound was 910.4454 ms. Destination wrapper software/write slots were 33/31 **in entry units**, distinct from the table's DWORD indices. Software MHI state was 2, wake reference 0; the HIF request/success/release counts were each 472 with zero recorded errors.

The retained CPU ring contains 9,144 decoded records, no gaps and no ASCII-incoherent records, with stable capture metadata. It records 101 EP2 credit debits and 100 returns, consistent with initial credit 1 and final credit 0. A paired capture also found queue depth 25 and credit 0 unchanged. There are 67 WMI RX records, including six firmware management-RX events. These events are distinct from cached network-list entries; they do not establish association. The 17 driver scan-start records do not prove 17 completed RF scans.

The timeline below uses the actual caller's init-begin journal as zero. All 675 embedded SystemTime anchors agree on the ring clock correction. Record numbers are zero-based.

| Event | Record | Seconds from init begin |
| --- | ---: | ---: |
| Caller init returned success | — | 2.703890 |
| Last WMI RX: UPDATE_STATS | 6969 | 3.753897 |
| Last EP2 credit return: 0→1 | 7034 | 3.781893 |
| Final debit: 1→0, START_SCAN 40965 | 7068 | 5.755651 |
| Four native getter queries/returns | 7614–7667 | 192.297857 |
| Retained trace ends | 9143 | 681.211057 |

No later WMI RX or credit return appears, including after the successful getter queries. The retained intervals are 677.429164 seconds after the last credit return, 677.457160 seconds after the last WMI RX, and 675.455406 seconds after the final debit. A host-side buffer completion after the debit does not prove target command execution.

These sequential observations show no persistent CE2 status producer-versus-RRI/local-consumer backlog in the measured stalled phase. They narrow the earlier hypothesis of a continuously pending, unserviced CE2 RX completion. They do not prove that firmware is dead, exclude transient interrupt/service failures or all coherency faults, or establish delivery of the final TX command to the target. Destination HP/TP equality is neither observed nor required for this conclusion. The getter uses the existing native wake, lock and window-selection protocol, so its successful reads are active observations, not an unperturbed or atomic snapshot.

The next useful distinction is whether the exhausted-credit command reached the target-facing CE TX producer/consumer path, rather than another timing or cache-policy variant. That requires separate source-qualified TX publication/ownership evidence; no additional live operation is claimed here.

[Structured result and evidence hashes](HARDWARE-RESULT.json). Raw traces, system identities and network identifiers remain private. The decoder's OEM base hash identifies the unchanged layout contract; it does not identify the loaded diagnostic binary. Individual ring reservation completion and allocation lifetime are not proven merely by successful decoding.
