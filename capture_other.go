//go:build !linux

package main

import "errors"

// Packet capture relies on Linux AF_PACKET sockets. On other platforms the
// daemon (`wgflow serve`) is unavailable, but the read-only commands
// (`web`, `top`, `report`, `stats`, `rollup-import`) still build and run so the
// web UI can be developed locally.

func openPacketSocket(iface string) (int, error) {
	return -1, errors.New("wgflow serve (packet capture) is only supported on linux")
}

func packetSocketStats(fd int) (uint64, uint64, error) {
	return 0, 0, errors.New("packet socket stats are only supported on linux")
}
