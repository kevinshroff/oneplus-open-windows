# Newer matched WCN7850 package candidate

After the Boot167 PRE/POST comparison, a fresh upstream check found an ARM64
`qcwlanhmt8380` package newer than the retained development baseline. This is
a matched compatibility trial; it initializes successfully, but association
and DHCP are still not working. It is not a known credit-stall fix.

| Input | Existing baseline | New candidate |
|---|---|---|
| INF driver version |1.0.4458.2600|1.0.4478.2200|
| INF driver date |2025-10-16|2025-11-09|
| Main firmware build |HMT.1.1.c5-00327.1|HMT.1.1.c5-00341.1|
| SYS SHA256 |802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56|f59d9e98bb736ccd78aa4ebd569616456fa0f09bf345a7b1002b0105693aeeef|

Source: the WOA project's [immutable reference-driver package](https://github.com/WOA-Project/Qualcomm-Reference-Drivers/blob/055d67b53eafd7c45d6909413e05a3f1177497b6/8380_CRD/200.0.57.0/qcwlanhmt8380.cab),
published in its March 2026 update. The repository describes its inputs as
Windows Update packages and distinguishes flighted from production support;
its publication is not an official support commitment for this phone.

The downloaded CAB was bound to that commit, checked against its Git blob
identity, and expanded privately. Windows reports valid Authenticode signatures
for both the Qualcomm SYS and Microsoft hardware-compatibility catalog. This
checks their signatures; driver-store import still needs normal catalog/member
validation. No proprietary package files are included here.

The generic PCI `17cb:1107` BERYLLIUM install section is unchanged. All25 board
data files, the PHY image and regulatory database are byte-identical between
the packages, including the selected `bdwlan.elf`. The main firmware and driver
have changed. The main firmware is a different build; equal file length is not
code equivalence. The INF adds a separate HP-specific section/policy that is
not selected by this phone's generic hardware match.

The matched trial installed the complete package on a fresh, fenced
initialization, retaining the current board and platform policies. Do not mix
its SYS with the previous main firmware or reuse old module-relative debugger
addresses. Do not reinitialize the consumed Boot167 instance. Success requires
sustained returned credits, actual network discovery/association and traffic;
a successful installation or scan notification alone is insufficient.

Host extraction/signature qualification and the targeted compiled compatibility
review are complete. The inspected WCN7850/resource/HTC/CE paths remain consistent
with the baseline's core semantics; no specific credit fix was identified.
On Boot168, complete signed-package import returned successfully. The first selector
then refused before `DiInstallDevice`: it compared the system INF path returned
by `SetupDiGetDriverInfoDetail` directly with the DriverStore path. No install
callsite, new-driver load or scan was reached. The existing driver stayed
disabled/stopped. This is an installer-source result, not a hardware failure.

The selector must resolve the returned INF through
[`SetupGetInfDriverStoreLocation`](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupgetinfdriverstorelocationw),
check both INF hashes and require the exact imported package. The original
returned detail path was not retained, so the documented system-INF behavior
is an explanation to validate in the corrected selector. See [the preceding Wi-Fi hardware result](../G1326-live-vdev2-observer/BOOT167-RESULT.md).

The [portable source](source) now includes the single-INF selector and task.
Actual Windows host compilation of both C# units, PowerShell AST/default-inert
checks and pure native64 layout/selection-flag checks passed with zero native
constructors, SetupAPI, WLAN or device calls. See [qualification](SOURCE-QUALIFICATION.json).
The corrected selector and diagnostic journal have a separate [native source
qualification](SOURCE-QUALIFICATION-R2.json) covering the exact six current public
source hashes. The private same-boot continuation resolves the package already
imported by the refused task; this public initial-use task retains its single
package import. The public offline renderer requires actual boot/session/admission
evidence and emits false approvals.

The task imports the complete signed package into DriverStore once, resolves
its actual stored INF, selects that exact compatible node and calls
DiInstallDevice once. It then checks installed runtime-member hashes and policy,
issues one scan and reads one cached network list. It retains no guessed OEM
INF name or interface GUID. Startup is fenced to disabled afterward. A changed
policy or failed/reboot-requiring installation stops subsequent actions.
These source checks do not establish successful package selection or networking.

## Boot168 runtime result

The corrected selector confirmed that Windows returned the published system
INF, mapped it to the exact imported store package and verified both hashes.
The one driver installation returned success without a reboot, all18 selected
runtime members matched, and the existing platform policies stayed intact.

One scan request returned success with an interface scan-complete notification.
The available-network cache had four entries representing two distinct SSIDs,
including saved-profile duplicates. This does **not** establish fresh RF scan
results. A saved-profile connection request was accepted but failed with
reason163851, “The specific network is not available.” The subsequent passive
BSS cache query returned zero entries; no DHCP address or traffic was achieved.
No new-driver credit-state measurement or old-RVA observer was used.
See [structured result](BOOT168-RESULT.json). The new driver is retained running
for investigation; its startup setting is disabled for the next boot.

A later exact-new-SYS CPU log capture strengthens the first-scan evidence: the
requested scan received two management frames and a firmware scan-complete
event. The firmware reported build00341.1. A subsequent Windows scan, sent
60.001seconds later, spent the final EP2 credit and received no WMI response.
The log then retained21 queued commands and zero returned credits for379seconds.
Its later scan-complete indication was a local cancellation, not a firmware
acknowledgement. No wake or idle transition was logged near this boundary, so
an idle-power cause remains a hypothesis. The next selected Wi-Fi experiment
will connect immediately after the first successful scan on a clean boot.
