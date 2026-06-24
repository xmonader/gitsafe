//go:build !unix

package policy

import (
	"fmt"
	"os"
)

// acquireLock takes an exclusive lock via O_CREATE|O_EXCL on platforms without
// flock. There is no automatic release on process death, so a crash leaves a
// stale lock that must be removed by hand — but it never grants the lock to two
// callers, which is the property that matters. (Unix builds use flock instead.)
func acquireLock(lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("policy is locked by another gitsafe process (%s); retry, or remove the file if a previous run crashed", lockPath)
		}
		return nil, err
	}
	f.Close()
	return func() { os.Remove(lockPath) }, nil
}
