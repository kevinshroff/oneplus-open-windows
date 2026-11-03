# Connect from initialization cache, with zero explicit scans

The matched4478 package initialized once. One task queried the existing network
cache, selected the exact saved profile and SSID, and requested connection6.309
seconds after initialization. It issued zero explicit scans, no optional
statistics queries and no fallback connection. The request was accepted, but
DHCP did not arrive within24.801seconds; no HTTP request was attempted.

All18 runtime files and existing policies verified. WLAN remained Running with
future startup disabled. This negative result means removing the additional
explicit scan and statistics queries did not suffice for connectivity. It does
not prove a firmware fault or identify the cause of the response stall.

[Structured result](RESULT.json). The initialization/OS scan behavior still
requires the actual trace; cached network entries alone do not prove fresh RF.

The source-qualified CPU trace contained7860 coherent records with no gaps.
Windows initiated scan40965 independently of this task's zero explicit scans;
that scan consumed the last credit2.001seconds after the last received event,
608ms before the task called connect. No later RX was recorded for93seconds.
Initialization's preceding scan had received two management frames and target
completion. The trigger of the later Windows scan remains unknown.

This does not establish a fixed102-command budget: this run consumed101 credits
and received100 returns, plus its initial credit. The next useful distinction
is hardware receive progress versus CPU shadows and DMA visibility, rather than
another task-delay variant.
