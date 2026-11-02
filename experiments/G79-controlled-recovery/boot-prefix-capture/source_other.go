//go:build !windows

package main

import (
	"fmt"
	"os"
)

func sourceInfo(f *os.File, name string) (int64, any, error) {
	s, e := f.Stat()
	if e != nil {
		return 0, nil, e
	}
	if !s.Mode().IsRegular() {
		return 0, nil, fmt.Errorf("only regular image files supported on this host")
	}
	return s.Size(), map[string]any{"kind": "regular image", "length": s.Size()}, nil
}
