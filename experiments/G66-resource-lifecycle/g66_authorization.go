// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"strings"
)

type Node struct {
	Instance string `json:"instance"`
	Status   uint32 `json:"status"`
	Problem  uint32 `json:"problem"`
	Service  string `json:"service"`
}
type Result struct {
	Mode               string      `json:"mode"`
	Nonce              string      `json:"nonce"`
	Environment        Environment `json:"environment"`
	Before             Node        `json:"before"`
	After              Node        `json:"after"`
	API                string      `json:"api"`
	Flags              uint32      `json:"flags"`
	CR                 uint32      `json:"CR"`
	APIReportedSuccess bool        `json:"api_reported_success"`
	Verified           bool        `json:"verified"`
}

func owner(n Node) bool {
	return strings.EqualFold(n.Instance, `ACPI\OPEN0063\0`) && strings.EqualFold(n.Service, "OpenG63")
}
func started(n Node) bool  { return owner(n) && n.Problem == 0 && n.Status&8 != 0 }
func disabled(n Node) bool { return owner(n) && n.Problem == 22 && n.Status&8 == 0 }
func authorize(mode, nonce string, e Environment, n Node, prior *Result) error {
	if er := allowedRAM(e); er != nil {
		return er
	}
	if !goodToken(nonce) || !owner(n) {
		return errors.New("exact owned node and fresh nonce required")
	}
	if mode == "disable" {
		if !started(n) || prior != nil {
			return errors.New("disable requires only the started owned recorder")
		}
		return nil
	}
	if mode != "enable" || !disabled(n) || prior == nil {
		return errors.New("enable requires the disabled owned recorder and exact prior receipt")
	}
	if prior.Mode != "disable" || prior.Nonce != nonce || prior.API != "CM_Disable_DevNode" || prior.Flags != 4 || prior.CR != 0 || !prior.APIReportedSuccess || !prior.Verified || !started(prior.Before) || !disabled(prior.After) || prior.Environment != e {
		return errors.New("same-trial successful disable receipt required")
	}
	return nil
}
