# Pre-scan statistics liveness discriminator

This is a diagnostic experiment, not a Wi-Fi fix. The inert helper adds one supported Windows statistics query after the original driver's initialization and before the sole explicit scan. No result from this experiment is claimed here. Reliable networking, association, DHCP and traffic remain unproved.

## Question

The retained P2P-disabled and subsequent legacy-mode attempts have a common tail: the last WMI payload is UPDATE_STATS, followed by vdev2 power-save parameter 3 = 190, power-save mode 0 and listen interval 1. All three commands receive host sender completions and returned endpoint 2 credits. After a quiet interval, the next scan preparation consumes the final credit and no later WMI payload or returned credit is observed.

The last admitted command differs: HT capability SET_IE in one attempt, START_SCAN in the legacy-mode attempt. The latter confirms zero-length HT/VHT capability construction and no retained SET_IE submission. Thus HT SET_IE is not necessary for the stall. Neither retained host log contains a management-TX-send or management-TX-completion command label. That also weakens the earlier directed-probe boundary hypothesis, subject to log coverage; these logs are not physical-wire observations.

The shared interval is therefore more useful than treating the changing final command as the fault site. A quiet interval does not establish when firmware stopped, and host sender completion does not acknowledge firmware command execution. The three returned credits do not prove semantic completion of those power/listen operations.

The discriminator asks whether another ordinary endpoint 2 request can obtain actual firmware responses and recycle a credit after this setup, before the next scan preparation.

## Native API and compiled driver evidence

[WlanQueryInterface](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanqueryinterface) supports the statistics opcode and requires the caller to free returned memory. The [opcode enumeration](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_intf_opcode) assigns statistics `0x10000101`. Microsoft's [Native WLAN to WDI mapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-oid-to-wdi-message-mapping) maps DOT11_STATISTICS queries to WDI_GET_STATISTICS, while explicitly making mapping state dependent.

Fresh offline REA/Ghidra 12.1.4 analysis of original ARM64 qcwlanhmt8380.sys 1.0.4458.2600, SHA256 `802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56`, establishes the driver-side chain. Addresses below are image RVAs, not runtime pointers:

- `WdiPropertyGetStatistics` (RVA `0x12fca0`) resolves the current port, resets an event and calls `MpQueryFwStatistics` (RVA `0x0303e0`) with stats request `0x109`. No cached-statistics return occurs in this handler.
- `MpQueryFwStatistics` (RVA `0x0303e0`) checks supported port type and current context/callback. A not-associated result logs but does not return early there. It invokes the callback at context + `0x36838` with the request and current vdev/peer metadata.
- `ol_ath_stats_attach` (RVA `0x1ea7b0`) explicitly installs `ol_ath_request_stats` (RVA `0x1ea630`) at that callback and registers UPDATE_STATS (`0x1d004`) handling.
- `ol_ath_request_stats` (RVA `0x1ea630`) allocates a fresh 24-byte TLV, writes stats request `0x109` and actual vdev/peer fields, and submits WMI_REQUEST_STATS (`0x16001`) through RVA `0x169898`. Allocation and missing-context errors are explicit.

Corresponding evidence IDs: handler `ev_64d8b895f7662a801b5ee96660c830064386acf5f3ec57756f8616fb5dd9fd78`; query `ev_c1b551ae26164e317d1ccb107b0783514415d0efd48ab516f7c21af2bfb2cad9`; attachment `ev_8e0b377963ee2a56817dd83d14dcf1e936ff34065986451cd42fe82ff1f45479`; sender `ev_91e1b61238790f8589806ad4c9fe2ce074eeba7c35b546ecde0da2a4f906e371`. Proprietary binaries and raw decompilation are excluded.

These are compiled observations, not proof of execution on the next boot. The native API reaching that WDI handler on the disconnected interface remains an inference until the actual attempt's host log confirms it. A successful API return or plausible returned counters cannot substitute for that evidence.

## Helper and integration boundary

`Stats.cs` is a library without an entry point. Loading or compiling it invokes no WLAN operation. Its `Run` method requires an explicit selected interface, native 64-bit process and caller admission. It consumes its in-process single-use guard before opening WLAN and performs at most one statistics query. It records API status, returned size and timing, frees returned memory, and closes its own handle. It deliberately reports firmware progress as unestablished.

The caller must independently qualify the fresh boot, original driver/resources, exclusive operator, exact interface and unused boot-wide attempt. The boolean argument is an integration guard, not independent proof of those conditions. Use the existing guarded once-init/once-scan task and owned trace. Preserve the original SYS/BDF and selected legacy/P2P/idle/band policies; introduce only this one diagnostic query after successful initialization and exact-interface qualification, before the existing sole explicit scan. Keep query timestamps and actual call count alongside existing initialization/scan accounting.

Compile and review the source before enabling any runtime operation. In a selected Windows PowerShell native 64-bit process, the following compiles the library without invoking it:

```powershell
Add-Type -TypeDefinition (Get-Content -LiteralPath '<reviewed-source-directory>\Stats.cs' -Raw)
```

The experiment still needs its caller's fresh admission, boot-wide once marker, source hashes, owned trace, future-start fencing and current GPU owner/broker exclusion. This directory does not provide a complete bring-up or staging workflow. No native compilation, API execution or networking result is asserted by the presence of this source.

If the query blocks, do not replay it or treat process termination as rollback. Preserve the existing task's no-hard-terminate/unbounded execution policy. There is no second query. Once the query returns, the existing explicit scan may occur once; the retained firmware correlation determines whether the diagnostic was informative.

## Acceptance and interpretation

First require actual same-attempt WDI_GET_STATISTICS and fresh WMI_REQUEST_STATS (`0x16001`), with actual endpoint 2 credit admission before scan preparation. Correlate the selected interface/vdev and query timing; unrelated automatic statistics traffic is insufficient. If Windows rejects or caches the query, or intervening automatic traffic prevents correlation, mark the discriminator uninformative.

Then distinguish these outcomes:

| Actual retained behavior | Supported interpretation |
|---|---|
| Admitted stats request, subsequent WMI stats payload and returned credit before scan preparation | Firmware/return-path liveness extends beyond vdev2 setup. A later scan stall keeps subsequent preparation relevant. |
| Admitted stats request, no subsequent WMI payload or returned credit, later scan queued without credit | The next scan/HT body is unnecessary for this recurrence. Failure lies earlier or at the stats/return boundary; no firmware fault site is proved. |
| WMI stats payload arrives but no credit returns | Investigate credit-report production, delivery and parsing separately from general WMI receive liveness. |
| Only API success, sender completion, local cancellation or scan notification | Firmware progress remains unestablished. |

The extra command also changes timing and queue contents. A changed outcome cannot uniquely blame the power/listen sequence or certify the unperturbed baseline. Preserve exact observations before choosing a corrective experiment. No credit injection, pool expansion, cache/LDAR patch or firmware replacement follows from this experiment alone.
