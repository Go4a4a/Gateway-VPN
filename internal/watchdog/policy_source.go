package watchdog

import (
	"context"
	"errors"
	"path/filepath"

	databasepkg "gateway-vpn/internal/db"
)

// LivePolicySource reopens the live database for every read so an atomic
// restore or update cannot leave the root watchdog attached to an old inode.
// OpenReadOnly configures mode=ro and query_only and therefore cannot create a
// root-owned WAL/SHM beside the application database.
type LivePolicySource struct {
	DatabasePath string
}

func (source LivePolicySource) Get(ctx context.Context) (Policy, error) {
	if !filepath.IsAbs(source.DatabasePath) || filepath.Base(source.DatabasePath) != "state.db" {
		return Policy{}, errors.New("fixed absolute live database path is required")
	}
	database, err := databasepkg.OpenReadOnly(ctx, source.DatabasePath)
	if err != nil {
		return Policy{}, err
	}
	defer database.Close()
	return ReadPolicy(ctx, database)
}
