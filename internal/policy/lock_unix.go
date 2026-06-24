//go:build unix

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// acquireLock takes a non-blocking exclusive advisory lock (flock) on lockPath.
// The lock lives on the open file description, so the kernel releases it when the
// descriptor is closed — including on process death — which eliminates stale
// locks without any time-based stealing. A second acquirer (even in the same
// process, via a distinct descriptor) is refused with EWOULDBLOCK.
func acquireLock(lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("policy is locked by another gitsafe process (%s); retry", lockPath)
	}
	return func() {
		// Release by closing the descriptor (which drops the flock). Do NOT unlink
		// the lock file: removing it while another process has the same inode open
		// would let a later acquirer create a fresh inode and flock that, yielding
		// two concurrent holders. The file is a stable, reusable coordination point
		// (kept out of commits by .gitsafe/policy/.gitignore).
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
