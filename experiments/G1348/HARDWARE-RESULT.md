# G1348 — hardware translation match

Boot177 completed one fixed-purpose SID0 privileged instruction-translation query. The SMMU hardware walk returned the exact physical page expected from the retained SQE firmware MDL. Broker result8 (`MATCH`), completion status1 and the owner’s success result agree. Owned control restoration was confirmed, with uncertainty0. Windows and its control agent remained responsive.

The existing filtered context-bank fault result was0, global/other fault results were0, and the captured raw CB0/CB2 status was0x400. These are the observed fields under the existing witness contract. No fault acknowledgement or retry was used.

The callback used the fault owner’s existing writable CB0 mapping; the broad diagnostic mapping remained read-only. The valid timer-output-pointer fix and retained TCU-vote firmware were reused. GMU startup succeeded with HFI running and acknowledgement mask15.

This resolved the first SQE firmware page through the hardware page-table walker; it did not fetch instruction data or execute commands. SQE start writes, packets issued and fence completions were all0. The owner deliberately returns its terminal failure status after a successful witness to retain references; its PnP problem10 and printed `CP fence1` label do not contradict the successful translation result.

Both native PnP calls returned. Future driver Starts were verified4 and owner once flags0; existing hardware references remain intentionally retained. The next step is a separately selected owner profile that continues to the first command/fence only after a clean same-run translation match and fresh access-authority checks.
