//go:build linux

package main

import (
	"net"
	"syscall"
	"unsafe"
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
	sa := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
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
