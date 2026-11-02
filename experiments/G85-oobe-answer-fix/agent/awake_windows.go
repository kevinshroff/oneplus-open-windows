package main

import (
	"fmt"
	"log"
	"runtime"
)

// The thread-scoped request lasts only while this guarded worker is alive.
// Keep the owning Go goroutine on the same OS thread through cleanup.
func diagnosticStayAwake() (func(), error) {
	runtime.LockOSThread()
	set := kernel.NewProc("SetThreadExecutionState")
	old, _, e := set.Call(0x80000003) // CONTINUOUS | SYSTEM_REQUIRED | DISPLAY_REQUIRED.
	if old == 0 {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("diagnostic keep-awake request: %v", e)
	}
	log.Print("Diagnostic keep-awake request active: display and system idle; no persistent power policy change")
	return func() { set.Call(0x80000000); runtime.UnlockOSThread() }, nil
}
