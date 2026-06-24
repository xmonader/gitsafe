//go:build unix

package policy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLockReleasedOnHolderDeath proves the crash-recovery property: a lock held
// by a process that dies (its descriptor closed by the kernel) is immediately
// re-acquirable, with no stale lock and no time-based stealing. This is what
// flock gives us and why the earlier mtime-TTL steal (a mutual-exclusion bug)
// was removed.
func TestLockReleasedOnHolderDeath(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")

	// Simulate a holder: open + flock, then close the fd as the kernel would on
	// process death (flock is released on the last close of the description).
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("could not take initial lock: %v", err)
	}
	// While held, a second acquire must fail.
	if rel, err := acquireLock(lockPath); err == nil {
		rel()
		t.Fatal("acquireLock must fail while another holder has the flock")
	}
	// "Crash": closing the fd drops the flock.
	f.Close()

	// Now it must be acquirable again — no stale lock left behind.
	rel, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("lock not re-acquirable after holder death: %v", err)
	}
	rel()
}
