package main

type proof struct {
	Selected                  bool              `json:"root_selected_live_phase_observation"`
	DriverBase                string            `json:"original_driver_base"`
	DriverSHA                 string            `json:"original_driver_sha256"`
	BoundaryQualified         bool              `json:"root_owns_live_vdev2_boundary_stop"`
	LoadHoldQualified         bool              `json:"root_owns_module_load_hold_before_DriverEntry"`
	CEHardware                bool              `json:"root_selects_naturally_selected_CE2_hardware_reads"`
	Phase                     string            `json:"phase"`
	ActionLedgerFile          string            `json:"action_ledger_file"`
	RootNormalBoot            bool              `json:"root_qualifies_actual_fresh_normal_boot"`
	ResourceQualification     bool              `json:"root_authorizes_source_owned_runtime_CM_resource_qualification"`
	BARBase                   string            `json:"expected_fixed_BAR0_base"`
	BARBytes                  uint64            `json:"maximum_reviewed_BAR0_bytes"`
	NoDiagnosticSinceBoundary bool              `json:"root_attests_no_root_selected_force_native_diagnostic_reset_or_error_clear_in_selected_interval"`
	Schema                    string            `json:"schema"`
	BootID                    uint32            `json:"boot_id"`
	Session                   string            `json:"phone_session"`
	Created                   string            `json:"created_utc"`
	Nonce                     string            `json:"root_nonce"`
	Image                     string            `json:"image_sha256"`
	NT                        string            `json:"nt_base"`
	PC                        string            `json:"held_pc"`
	OwnerBase                 string            `json:"owner_base"`
	OwnerSize                 uint32            `json:"owner_size"`
	OwnerTimestamp            uint32            `json:"owner_timestamp"`
	OwnerChecksum             uint32            `json:"owner_checksum"`
	OwnedBreak                bool              `json:"root_owns_break6"`
	CurrentTables             bool              `json:"root_qualifies_current_tables_and_resource_owner"`
	PhysicalAccess            bool              `json:"root_qualifies_fixed_physical_device_ranges_uncached"`
	Evidence                  map[string]string `json:"actual_evidence_sha256"`
}
