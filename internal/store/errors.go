// Package store contains errors shared by SQLite-backed domain repositories.
package store

import "errors"

var (
	ErrNotFound            = errors.New("record not found")
	ErrPrioritySetMismatch = errors.New("priority list does not match enabled records")
	ErrStaleGeneration     = errors.New("state generation changed while operation was running")
)
