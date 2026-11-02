# Source of the current translated resource

The reader qualifies a current driver-owned copy of the OS-translated resource and its live debugger mapping. It does not fabricate a missing pre-init grant from a static expected address or label this as a fresh enumeration of the global CM resource database.

These compiled observations apply to original ARM64 qcwlanhmt8380.sys SHA256 `802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56`. Addresses below are image RVAs or structure offsets, not saved runtime pointers. Proprietary binaries and raw REA output are excluded.

| Source function | Observed propagation |
|---|---|
| WlanPciDrvEvtDeviceAdd, `437000` | Stores its typed WDF context at global `3968d0`, and its allocated adapter at context+430. Evidence `ev_93d0ac1fbd822535506c1a3c5b820fe5c7b97407e80fce783faf183bb3dac744`. |
| PciDrvEvtDevicePrepareHardware, `438060` | Obtains that same typed context and passes it with raw and translated resources to `438cf8`. Evidence `ev_4ef76d2663ba04d2717834d1f666a7961b5bc28bd485f7a7dd318ca4cd99f855`. |
| WlanBusNICMapHWResources, `438cf8` | Copies each raw 20-byte CM descriptor to C+8+20*i and translated descriptor to C+120+20*i; increments C+238. Its sole translated type3 Memory entry supplies actual PA and length to the mapper. It retains PA at C+248, mapped VA at C+350 and length at C+358, and propagates them through adapter+10→+10 to a resource record at offsets +28/+8/+10. Evidence `ev_364c04f073ab469684b08ce61ed978cac8497b39e6aa07a803215c9f056fa89d`. |
| Mapping helper, `228520` | Calls MmMapIoSpaceEx with protection `0x204` when available, otherwise MmMapIoSpace with cache type0. The observer never invokes either mapper. Evidence `ev_1ff33afc91ce52c6d26407da665a80271ab179276c329e04218a397b68e4522d`. |

At runtime, the reader checks current original module/code identity, no-unload ownership and the current source-owned adapter/context/WMI/HTC/HIF/HAL/MHI chain. C+430 must equal the current adapter global. The retained arrays must contain exactly one translated Memory descriptor matching both C's PA/VA/length and the current resource record. Count is bounded to 1–14, the capacity before the next retained region/count; there is no pool scan or unbounded descriptor walk.

The actual retained VA must equal HIF/HAL/MHI BAR VA. Its actual length must cover all requested offsets and remain within the reviewed maximum. Its translated PA must match the fixed permitted physical resource, and current PCI BAR registers must independently agree. A static expected PA alone cannot pass these checks.

`IDebugDataSpaces4::VirtualToPhysical` (SDK slot23) must return full S_OK and exact PA at the mapping start/last byte and every planned MMIO read endpoint. The fixed fault observations require 18 endpoint queries; optional natural-window CE observations add four. Each query is recorded. Failure refuses without fallback. This is translation evidence, not a firmware command.

G1295's active clocks/resets/PERST/WLAN_EN, root link, endpoint identity, memory decode, PM/D0, fixed physical read allowlists and before/after safety checks remain. Resource/static identities are captured again afterward. The fault tuple allowlist is unchanged. Missing/mismatched resource, descriptor, translation or access data refuses before fault/CE MMIO.

The debugger interfaces use SDK slot6 for ReadVirtualUncached, slot23 for VirtualToPhysical and slot42 for ReadPhysical2. No write slot is called. Obtain the Microsoft SDK declarations independently; the SDK is not bundled. Relevant API contracts: [VirtualToPhysical](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugdataspaces2-virtualtophysical), [WdfCmResourceListGetDescriptor](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfresource/nf-wdfresource-wdfcmresourcelistgetdescriptor), and [CM_PARTIAL_RESOURCE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor).

These source facts and CPU tests do not establish native execution, a valid future resource, endpoint DMA visibility or firmware health. The ARM host-intent-only phase needs no BAR and does not connect to a debugger. All observation permissions default false.
