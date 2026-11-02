package main

import (
	"encoding/binary"
	"fmt"
)

// The only bulk OUT command implemented. No programmer, RAM write, Firehose,
// partition or disk API exists in this helper.
func resetRequest() []byte { return []byte{7, 0, 0, 0, 8, 0, 0, 0} }
func resetResponse(b []byte) bool {
	return len(b) == 8 && binary.LittleEndian.Uint32(b) == 8 && binary.LittleEndian.Uint32(b[4:]) == 8
}
func validateInterface(d []byte) error {
	if len(d) != 9 || d[0] != 9 || d[1] != 4 || d[2] != 0 || d[3] != 0 || d[4] != 2 || d[5] != 0xff || d[6] != 0xff || d[7] != 0x10 {
		return fmt.Errorf("unexpected Qualcomm recovery interface descriptor")
	}
	return nil
}
