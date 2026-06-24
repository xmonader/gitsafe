//go:build unix

package policy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLockNoUnlinkRace guards against the flock+unlink hazard: a release that
// removes the lock file lets a concurrent opener keep the now-unlinked inode
// while a later acquirer creates a fresh inode and flocks that — two holders at
// once. With a persistent lock file (no unlink on release), a new acquirer is
// correctly refused while another process still holds it.
func TestLockNoUnlinkRace(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")

	// A acquires the lock (creates the inode, flocks it).
	relA, err := acquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	// B opens the same path/inode (separate description) before A releases.
	fB, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fB.Close()
	// A releases. If release unlinks the file, B's inode becomes detached.
	relA()
	// B now takes the flock on the inode it holds open.
	if err := syscall.Flock(int(fB.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("B should be able to flock after A released: %v", err)
	}
	defer syscall.Flock(int(fB.Fd()), syscall.LOCK_UN)

	// While B holds the lock, a fresh acquire MUST be refused. If release unlinked
	// the file, acquireLock would create a new inode and wrongly succeed.
	relC, errC := acquireLock(lockPath)
	if errC == nil {
		relC()
		t.Fatal("acquireLock succeeded while another process holds the lock (flock+unlink race)")
	}
}

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
