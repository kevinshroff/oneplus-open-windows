# Immediate saved-profile connection trial

The matched4478/firmware341 package initialized once on a clean boot. The task
performed one scan and requested the exact existing saved profile7.162seconds
after initialization, without a host round trip. It did not associate or obtain
DHCP; Windows reported reason163851, “The specific network is not available.”
No HTTP request was sent. [Structured result](BOOT169-RESULT.json).

A stable source-qualified CPU log captured8107 coherent records. The final
credit was spent on WMI_REQUEST_STATS2.595seconds after the last received event,
12ms before WDI CONNECT; later commands accumulated with zero credit. The task
included an unnecessary statistics query, but this trace does not uniquely
attribute that WDI request to its caller. A prepared, unselected source variant
removes both statistics queries.

Across Boot168 and169, the first command after the successful requested scan
was the final unreturned debit: START_SCAN after59seconds in168, REQUEST_STATS
after2.6seconds in169. Both returned101 credits and consumed102 including the
initial credit. Neither a60-second idle interval nor the statistics command
is necessary to the shared phenotype. This does not establish a fixed command
budget, firmware failure, hardware sleep or a receive-interrupt cause.

The corrected CPU-state observer matched65 paired reads without a change while
CPUs were held. Software wake counters showed468 successful requests and no
recorded failures/timeouts; the cached MHI state was awake. CE2 had no observed
status backlog and the endpoint had zero credits with90 queued commands. These
are RAM observations, not proof of hardware receive state or allocation lifetime.
No wake callback or MMIO write was attempted.

The trace also distinguishes initialization's scan from the extra requested
scan: commands and replies continued after the initialization scan, while
silence followed the additional scan. The next selected test connects directly
from initialization's cache, issuing zero explicit scans and no optional
statistics queries. This tests scan ordering/count and timing together; it does
not establish which one causes the stall.
