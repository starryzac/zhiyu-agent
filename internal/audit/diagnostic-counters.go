package audit

import "sync/atomic"

var verifyCapturedAttempts atomic.Uint64

// VerifyCapturedAttemptSnapshot is the process-local number of VerifyCaptured
// entries, including rejected headers. It is not a successful replay count or
// coverage of every historical verification function. No reset is provided.
func VerifyCapturedAttemptSnapshot() uint64 { return verifyCapturedAttempts.Load() }
