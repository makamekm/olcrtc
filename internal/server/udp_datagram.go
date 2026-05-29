package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func writeLengthPrefixedDatagram(conn net.Conn, payload []byte) error {
	if len(payload) == 0 || len(payload) > 65535 {
		return fmt.Errorf("invalid datagram size: %d", len(payload))
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	if _, err := conn.Write(header[:]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readLengthPrefixedDatagram(conn net.Conn, maxSize int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > maxSize {
		return nil, fmt.Errorf("invalid datagram size: %d", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
