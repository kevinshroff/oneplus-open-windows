//go:build !windows

package main

import "errors"

func diagnosticStayAwake() (func(), error) {
	return nil, errors.New("diagnostic keep-awake request requires Windows")
}
