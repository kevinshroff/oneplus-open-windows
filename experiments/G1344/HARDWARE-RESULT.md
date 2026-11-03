# G1344 hardware result

The no-hint candidate initialized successfully with no reboot required. The driver remained running, with future automatic startup disabled. A bounded read of the loaded constructor matched all eight changed instructions, and the retained NC instruction also matched.

One cached-network query, 15,020 ms after the initialization call began, returned success with zero networks. The saved network was therefore unavailable for selection: no association or DHCP attempt followed. The task made no explicit scan, statistics query, HTTP request or profile change.

Hint suppression alone did not resolve the recurring admitted-command/credit/RX-silence boundary. The current journal contains 109 counter-advanced host records; all eight retained START_SCAN payloads are 312 bytes with both optional hint arrays empty. Scan 40965 retains priority 1 and the same first 304 payload bytes as the earlier 372-byte record. The change therefore took effect in both the loaded constructor and retained host representation.

The existing host-ring decoder recovered 7,720 coherent, unwrapped records with stable metadata and no gaps. All 109 journal commands match its corresponding command prefix. The host admitted scan 40965, consumed endpoint 2’s last credit, and logged completion 0 for that same command buffer. Initial credit 1 plus 100 unit returns minus 101 unit debits balances exactly 0. No later logged WMI receive or credit return appears while CPU logging continues for 229 seconds. The last return-to-debit gap is1.964 seconds; the last WMI receive-to-debit gap is1.998 seconds. Later scan cancellation/completion is local and is not a received firmware acknowledgement.

A sequential CPU snapshot found source local HP/cached TP/DMA RRI TP 20/20/20, reap 16 with next 20, software slots 5/5, and all 32 ownership-context values zero. endpoint 2 had queue 8/credits 0; the later ring ends at queue 10. These are current CPU observations, not current hardware HP/TP reads. Earlier experiments’ hardware reads cannot be reused as this epoch’s hardware state.

The transport evidence goes beyond the empty-cache result, but does not prove final target command execution, complete coherency, or an awake endpoint. The initial silence predates these post-task captures; the captures themselves are sequential and pause-perturbed. Nonempty optional hints are not necessary for this observed failure. The next source investigation is the common wake-retention/transport-progress seam rather than another isolated scan-field change. No repeated initialization, force-wake call or extra trial is selected by this result.

See the [sanitized result](HARDWARE-RESULT.json). Raw traces and network identities remain private.
