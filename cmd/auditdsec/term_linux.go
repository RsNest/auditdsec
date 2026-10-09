//go:build linux

package main

import (
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// withoutEcho runs fn with terminal echo switched off on fd, so a password
// typed at the prompt does not stay on the screen and in the scrollback. It
// reports false when fd is not a terminal, and then fn is not run.
//
// This is a direct ioctl because the agent has no module dependencies and
// x/term would be the first one, for thirty lines of Linux-only code.
func withoutEcho(fd uintptr, fn func()) bool {
	var original syscall.Termios
	if !ioctl(fd, syscall.TCGETS, &original) {
		return false
	}
	quiet := original
	quiet.Lflag &^= syscall.ECHO
	if !ioctl(fd, syscall.TCSETS, &quiet) {
		return false
	}

	// Ctrl-C during the prompt would otherwise leave the shell with echo off,
	// which looks like a broken terminal.
	restore := func() { ioctl(fd, syscall.TCSETS, &original) }
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-interrupted:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(interrupted)
		restore()
	}()

	fn()
	return true
}

func ioctl(fd uintptr, request uintptr, t *syscall.Termios) bool {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(t)))
	return errno == 0
}
