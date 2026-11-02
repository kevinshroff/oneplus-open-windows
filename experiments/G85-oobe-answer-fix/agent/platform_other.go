//go:build !windows

package main

import (
	"errors"
	"os/exec"
)

func startProcessLifetime(node string, ownerPID int) error { return nil }

func prepareCommand(*exec.Cmd) (func(), error) { return func() {}, nil }
func assignCommand(*exec.Cmd) error            { return nil }
func phoneGuardAndNetwork(Config) error {
	return errors.New("phone worker requires Windows ARM64 WinPE")
}
func screenshot() ([]byte, error) { return nil, errors.New("screenshot requires Windows") }
