package snmpwire

import (
	"errors"
	"fmt"
	"io"
)

// ReadTCP reads one SNMP message from r using RFC 3430 BER-length framing:
// identifier, definite length, then exactly that many content octets.
// There is no 32-bit length prefix. maxBytes caps identifier+length+content;
// zero uses DefaultMaxMessageBytes. Framing loss returns ErrBER, ErrTruncated,
// or ErrTooLarge so the caller can close the connection.
func ReadTCP(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMessageBytes
	}

	hdr := make([]byte, 0, 2+maxBERLengthBytes)
	var b [1]byte
	if err := readFull(r, b[:]); err != nil {
		return nil, err
	}
	if b[0]&0x1f == 0x1f {
		return nil, fmt.Errorf("snmpwire: high-tag-number form: %w", ErrBER)
	}
	if b[0] != tagSequence {
		return nil, fmt.Errorf("snmpwire: expected tag 0x%02x got 0x%02x: %w", tagSequence, b[0], ErrBER)
	}
	hdr = append(hdr, b[0])

	var contentLen int
	for {
		if int64(len(hdr)+1) > maxBytes {
			return nil, fmt.Errorf("%w (%d > %d)", ErrTooLarge, len(hdr)+1, maxBytes)
		}
		if err := readFull(r, b[:]); err != nil {
			return nil, err
		}
		hdr = append(hdr, b[0])
		rd := newReader(hdr[1:])
		n, err := rd.length()
		if err == nil {
			if rd.remaining() != 0 {
				return nil, fmt.Errorf("%w", ErrBER)
			}
			contentLen = n
			break
		}
		if !errors.Is(err, ErrTruncated) {
			return nil, err
		}
		if len(hdr)-1 > maxBERLengthBytes {
			return nil, fmt.Errorf("snmpwire: invalid length form: %w", ErrBER)
		}
	}

	total := int64(len(hdr)) + int64(contentLen)
	if total > maxBytes {
		return nil, fmt.Errorf("%w (%d > %d)", ErrTooLarge, total, maxBytes)
	}

	out := make([]byte, len(hdr)+contentLen)
	copy(out, hdr)
	if contentLen > 0 {
		if err := readFull(r, out[len(hdr):]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// WriteTCP writes a complete BER SNMP message with no extra prefix.
func WriteTCP(w io.Writer, msg []byte) error {
	for len(msg) > 0 {
		n, err := w.Write(msg)
		if n > 0 {
			msg = msg[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w", ErrTruncated)
	}
	return err
}
