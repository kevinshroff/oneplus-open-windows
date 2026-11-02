# Newer matched WCN7850 package candidate

After the Boot167 PRE/POST comparison, a fresh upstream check found an ARM64
`qcwlanhmt8380` package newer than the retained development baseline. This is
an untested compatibility candidate, not a known fix or a networking result.

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

Next trial should install the complete matched package on a fresh, fenced
initialization, retaining the current board and platform policies. Do not mix
its SYS with the previous main firmware or reuse old module-relative debugger
addresses. Do not reinitialize the consumed Boot167 instance. Success requires
sustained returned credits, actual network discovery/association and traffic;
a successful installation or scan notification alone is insufficient.

Host extraction/signature qualification and the targeted compiled compatibility
review are complete. The inspected WCN7850/resource/HTC/CE paths remain consistent
with the baseline's core semantics; no specific credit fix was identified.
No phone driver-store import, binding, load or firmware replacement has run. See [the preceding result](../G1326-live-vdev2-observer/BOOT167-RESULT.md).

The [portable source](source) now includes the single-INF selector and task.
Actual Windows host compilation of both C# units, PowerShell AST/default-inert
checks and pure native64 layout/selection-flag checks passed with zero native
constructors, SetupAPI, WLAN or device calls. See [qualification](SOURCE-QUALIFICATION.json).
Runtime source is byte-identical to the private qualified copy; the public
offline renderer omits only a historical private session-ID exclusion. It still
requires actual future boot/session/admission evidence and emits false approvals.

The task imports the complete signed package into DriverStore once, resolves
its actual stored INF, selects that exact compatible node and calls
DiInstallDevice once. It then checks installed runtime-member hashes and policy,
issues one scan and reads one cached network list. It retains no guessed OEM
INF name or interface GUID. Startup is fenced to disabled afterward. A changed
policy or failed/reboot-requiring installation stops subsequent actions.
These source checks do not establish successful package selection or networking.
