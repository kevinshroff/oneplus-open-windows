// SPDX-License-Identifier: MIT
package main

var words = [...]struct {
	Name    string
	Address uint64
}{
	{"collapse_vote", 0x152020},
	{"clock_vote_52000", 0x152000},
	{"clock_vote_52008", 0x152008},
	{"core_reset", 0x16b000},
	{"core_gdscr", 0x16b004},
	{"core_cfg_gdscr", 0x16b008},
	{"slv_q2a_cbcr", 0x16b01c},
	{"slv_axi_cbcr", 0x16b020},
	{"mstr_axi_cbcr", 0x16b02c},
	{"cfg_ahb_cbcr", 0x16b038},
	{"aux_cbcr", 0x16b03c},
	{"pipe_cbcr", 0x16b048},
	{"rate_change_cbcr", 0x16b054},
	{"phy_gdscr", 0x16c000},
	{"phy_cfg_gdscr", 0x16c004},
	{"phy_reset", 0x16c01c},
	{"selector_control", 0xf153000},
	{"selector_inout", 0xf153004},
	{"perst_control", 0xf15e000},
	{"perst_inout", 0xf15e004},
	{"wake_control", 0xf160000},
	{"wake_inout", 0xf160004},
	{"wlan_enable_control", 0xf150000},
	{"wlan_enable_inout", 0xf150004},
}
