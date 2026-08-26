//go:build !linux

package main

import "os"

func credentialOwnerOK(os.FileInfo) bool {
	return false
}

func trustFileOwnerOK(os.FileInfo) bool {
	return false
}
