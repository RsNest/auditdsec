//go:build !linux

package main

// withoutEcho cannot switch echo off anywhere but Linux, which is the only
// system the agent runs on. The caller falls back to a visible prompt.
func withoutEcho(uintptr, func()) bool { return false }
