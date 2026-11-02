# Boot167: pending RX serviced; credit starvation remains

One original initialization and one explicit scan returned success. Notification 7 is an interface scan_complete notification, not a uniquely correlated firmware response or scan-fail. No network count is claimed.

The actual source-qualified PRE and POST reads completed with stable source-owned resource/mapping admission and no target writes. The BHI tuple was exactly unchanged: `cafecace/cafecace/014feeab/00000496`; MHI status remained `0x201`, EE 2. The tuple was already present before the later observed credit starvation and does not establish a newly generated firmware fault or its cause.

| Observation | PRE | POST |
|---|---:|---:|
| CE2 status local/cache/RAM shadow, DWORD indices |56/56/60|60/60/60|
| CE2 destination local/cache/RAM shadow, DWORD indices |24/28/30|26/30/30|
| EP2 credits / queued commands |1/0|0/33|

A status entry is four DWORDs, so local 56→60 is one status descriptor serviced. Destination local 24→26 is one two-DWORD entry advance, consistent with the source's receive-buffer posting path. The PRE pending descriptor did not remain stuck. POST reads the next descriptor slot; its zero byte-count field can be normal stale-loop content and is not evidence that the PRE descriptor remained unprocessed. These observations weaken persistent missed-RX servicing and refill failure as explanations for this boundary.

The retained ring records the vdev2 stats command consuming the final credit 1→0. One later FREQ_AVOID WMI event was dispatched, but no stats response or further EP2 credit report appeared; queued work reached depth 25 during the captured interval and depth 33 at POST. Earlier unpaused legacy trials exhausted their final credit on START_SCAN after a stats response, so this does not establish a stats-specific failure. P2P and HT/VHT exclusion trials had already failed to restore progress.

Both observations refused hardware indices because the natural selector was `0x40000014`, not the qualified `0x40000037`. Unavailable zero fields are not hardware measurements. Matching RAM indices do not prove the hardware ring empty or establish target nonproduction.

The PRE stop upper bounds were about 0.86 s and 5.81 s; the latter exceeded its selected budget. PRE is pause-perturbed, and the comparison does not claim timing neutrality or a causal fault transition. No additional ring copy, native diagnostic API, forced wake, window write, replay or firmware modification was selected by this result. Wi-Fi remains unfinished; the useful narrowing is a shared command/credit/target-progress boundary rather than an enduring unread PRE descriptor.
