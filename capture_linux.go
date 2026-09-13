//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003
const solPacket = 263
const packetStatistics = 6
const packetSocketReadBuffer = 64 * 1024 * 1024

type tpacketStats struct {
	Packets uint32
	Drops   uint32
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func openPacketSocket(iface string) (int, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return -1, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPAll)))
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, packetSocketReadBuffer); err != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, packetSocketReadBuffer)
	}
	// A timeout lets shutdown join an idle source reliably. Closing a file
	// descriptor from another thread does not universally wake a blocked Linux
	// packet-socket recvfrom immediately.
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// openPacketSocketInNetNS opens the AF_PACKET socket in another network
// namespace, then returns the calling thread to the host namespace. Network
// namespace membership is captured by the socket at creation time, so the fd
// can be consumed normally by any goroutine afterwards.
func openPacketSocketInNetNS(iface, netnsPath string) (int, error) {
	if netnsPath == "" {
		return openPacketSocket(iface)
	}
	type result struct {
		fd  int
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		// setns is per-thread. If restoring the original namespace fails, leave
		// the goroutine locked: the Go runtime will retire that OS thread when
		// the goroutine exits instead of returning a poisoned thread to its pool.
		runtime.LockOSThread()
		original, err := os.Open("/proc/self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			resultCh <- result{fd: -1, err: fmt.Errorf("open current netns: %w", err)}
			return
		}
		defer original.Close()
		target, err := os.Open(netnsPath)
		if err != nil {
			runtime.UnlockOSThread()
			resultCh <- result{fd: -1, err: fmt.Errorf("open target netns: %w", err)}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			resultCh <- result{fd: -1, err: fmt.Errorf("enter target netns: %w", err)}
			return
		}
		fd, openErr := openPacketSocket(iface)
		if restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			if fd >= 0 {
				_ = syscall.Close(fd)
			}
			resultCh <- result{fd: -1, err: fmt.Errorf("restore original netns: %w", restoreErr)}
			return
		}
		runtime.UnlockOSThread()
		if openErr != nil {
			resultCh <- result{fd: -1, err: openErr}
			return
		}
		resultCh <- result{fd: fd}
	}()
	r := <-resultCh
	return r.fd, r.err
}

func packetSocketStats(fd int) (uint64, uint64, error) {
	var st tpacketStats
	l := uint32(unsafe.Sizeof(st))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(solPacket), uintptr(packetStatistics), uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return 0, 0, errno
	}
	return uint64(st.Packets), uint64(st.Drops), nil
}
