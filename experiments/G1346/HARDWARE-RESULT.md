# G1346 hardware result — Boot175

**Both patched wake-site words were loaded, but sustained control progress and Wi-Fi connection were not restored.** One initialization returned success without a reboot; the selected on-disk image matched the signed candidate and WLAN remained Running/Start4. The task ended Ready/result0.

The single cached query returned five entries representing **three distinct SSIDs**, deduplicated by exact private SSID bytes. Three entries shared the requested SSID. The requested saved pair was present with quality46, connectable=true, reason0 and one reported BSSID. The query began15008ms after the initialization callsite; connection submission returned0 at17365ms, about2.36s after the cache query began. Cache visibility and request acceptance did not establish association.

The actual loaded words matched NOP at image-relative1b334c and B at228548. This verifies those two code changes, not electrical wake state or every other power path.

The retained CPU ring contains9109 records with no gaps. Times below are relative to its first retained record, not independently aligned initialization-entry/UTC times.

| Record | Time (s) | Observation |
|---|---:|---|
| 6837 | 3.311666 | Initial scan40964 completed; four management-RX records were logged. |
| 6997 | 3.3436695 | Final EP2 credit return. Last firmware WMI_RX was record6932. |
| 7022 | 5.3141258 | Scan40965 consumed the final credit,1→0. |
| 7193 | 17.306824 | Connect began after credit starvation. |
| 7289–7290 | 17.3088181 | Peer creation queued at zero credits; vdev/control work also remained queued. |

Credit accounting closes exactly: **initial1 +100 returned −101 debited =0**. The final scan followed the last return by1.9704563s. Its same-buffer HTC completion had rc0, which does not prove target command execution. No later firmware WMI_RX or credit return appeared through505.453411s of further CPU logging. Paired CPU metadata was stable at EP2 credit0/queue51; no current hardware-ring getter was performed.

Local hardware-request timeouts followed the queued peer setup. The connection completed locally with reason2, and Windows later reported event8002, “The specific network is not available.” Association-initiation events8000/11000 preceded8002 by about36.53s; no successful association/security completion was established. DHCP remained absent during its25-second budget. This trace does not diagnose AP rejection, security negotiation or RF failure.

The task made zero explicit scans, optional statistics requests, HTTP requests or profile writes; initialization/OS scans are outside those task counters. Boot168 had already shown stronger initial RF/scan progress before a similar quiet-gap/final-credit boundary. The cache count therefore does not establish sustained transport recovery. The cause of lost progress remains unknown; firmware death and complete coherency correctness are not established.

This combined configuration also changed the QTB firmware and retained TCU vote, so effects cannot be attributed to the WLAN patch alone. No further Wi-Fi trial or profile change is selected by this record. See [structured result](HARDWARE-RESULT.json); raw network/device identities and captures remain private.
