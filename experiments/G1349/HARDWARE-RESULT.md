# G1349 hardware result

The priority-only candidate did **not restore WMI/credit progress** in Boot177. The seven loaded patch words matched. The scan constructor logged priority2 for scan40965, but neither loaded code nor that log attests the device-visible payload.

One initializer call returned success with NeedReboot false; all18 runtime files matched before and after. The service remained Running with future Start4. The task queried cache once at15010ms: three entries represented one distinctSSID byte sequence, with duplicate profiles. The exact reviewed pair was connectable, quality46, reason0 and oneBSSID. One connection request was accepted; DHCP readiness remained false after25.032s. A later read showed only link-localIPv4 and no default route. Its event-filter query failed, so the empty event result is not qualified absence evidence. No network identities are published.

The retained CPU ring decoded9421 coherent records with no gaps; all seven files and paired metadata were verified. Scan40964 received real firmware STARTED, eleven channel events and COMPLETED(reason0). Scan40965 then consumed the final credit at record7021, followed by same-buffer HTC completion rc0 at7026. No later firmware WMI RX or credit return appears while CPU logging continues for617.541seconds. Its later completion-shaped event is local cancellation after a STOP queued at zero credit, not a firmware response. Scan40966 likewise queues at zero credit.

Credit arithmetic is initial1 +100 returned −101 debited =0. Last firmware WMI RX is UPDATE_STATS at6931; the last credit return is6996. The final debit follows1.9700941seconds later. Paired CPU EP2 values are stable at queue54/credit0. Idle silence before that debit alone is not a failure predicate. HTC completion does not prove the target executed the scan.

Connection processing reaches peer creation, but that command is queued without credit. Local hardware-request timeouts follow, then a local CONNECT_COMPLETE failure. This is not evidence of AP rejection, a security-stage failure or a DHCP-specific bug.

The same firmware and other driver policies were retained. Initial scan/cache visibility already occurred before G1349; this result weakens the priority-specific explanation without identifying the common delivery/target-progress cause. It does not establish firmware death or eliminate every coherency/power possibility. The ring reader added no firmware getter or Wi-Fi MMIO read, and no repeated Wi-Fi trial was used for this analysis. See the [structured sanitized result](HARDWARE-RESULT.json).
