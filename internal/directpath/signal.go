package directpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Signalling messages are length-prefixed blobs on a tunnel stream.

const maxBlob = 64 << 10

// Command is the connect-request cmd that opens direct-path signalling.
const Command = "direct"

// Signalling acknowledgements after the command.
const (
	AckSupported   byte = 0x00
	AckUnsupported byte = 0x01
)

var errBlobTooLarge = errors.New("signalling message too large")

// WriteBlob writes one length-prefixed message.
func WriteBlob(w io.Writer, data []byte) error {
	if len(data) > maxBlob {
		return errBlobTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data))) //nolint:gosec // bounded by maxBlob
	if _, err := w.Write(append(hdr[:], data...)); err != nil {
		return fmt.Errorf("write signalling message: %w", err)
	}
	return nil
}

// ReadBlob reads one length-prefixed message.
func ReadBlob(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read signalling header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxBlob {
		return nil, errBlobTooLarge
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read signalling body: %w", err)
	}
	return data, nil
}
