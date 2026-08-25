//go:build linux

package backup

import (
	"os"
	"testing"
)

func TestValidateRestoreTransactionOwnershipRequiresRoot(t *testing.T) {
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = validateRestoreTransactionOwnership(info)
	if os.Geteuid() == 0 && err != nil {
		t.Fatalf("root-owned transaction directory rejected: %v", err)
	}
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("non-root transaction directory was accepted")
	}
}
