// SPDX-License-Identifier: MIT
// Exact compiled-profile directory and nonce, checked before creating evidence
// or starting the kernel worker. Receiver identity is checked separately.
package main

import (
	"path/filepath"
	"strings"
)

const idleCaptureDirectory = `X:\OpenG17\payloads\G60-idle-stop-capture`
const activeCaptureDirectory = `X:\OpenG17\payloads\G60-active-contact-capture`

func exactEvidencePaths(ready, dest, token, directory string) bool {
	if directory != idleCaptureDirectory && directory != activeCaptureDirectory {
		return false
	}
	if len(token) != 32 {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	base := filepath.Join(directory, "G59-receiver-"+token)
	return strings.EqualFold(filepath.Clean(ready), base+"-ready.json") && strings.EqualFold(filepath.Clean(dest), base+"-power.bin")
}
