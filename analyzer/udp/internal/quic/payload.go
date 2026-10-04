package quic

import (
	"bytes"
	"cmp"
	"crypto"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

// MaxCryptoStreamSize bounds the ClientHello and the retained CRYPTO fragments.
const MaxCryptoStreamSize = 64 * 1024

const maxCryptoFrames = 1024

// CryptoStream collects the client Initial CRYPTO stream across datagrams.
// Like Hysteria's QUIC sniffer, it accepts shuffled and retransmitted fragments
// and only exposes the contiguous prefix starting at offset zero.
// The zero value is ready to use.
type CryptoStream struct {
	dcid    []byte
	version uint32
	frames  []cryptoFrame
	size    int
}

// Feed collects fragments from Initial packets coalesced in a datagram. It does
// not modify or retain the caller's buffer. A successfully decrypted but incomplete Initial is
// valid; callers must wait for the complete TLS handshake message themselves.
func (c *CryptoStream) Feed(data []byte) error {
	found := false
	for len(data) > 0 {
		hdr, offset, err := ParseInitialHeader(data)
		if err != nil || (hdr.Version != V1 && hdr.Version != V2) ||
			hdr.Length == 0 || hdr.Length > int64(len(data))-offset {
			break
		}
		packet := data[:offset+hdr.Length]
		data = data[len(packet):]
		initialType := uint8(0)
		if hdr.Version == V2 {
			initialType = 1
		}
		if hdr.Type != initialType || c.dcid != nil &&
			(c.version != hdr.Version || !bytes.Equal(c.dcid, hdr.DestConnectionID)) {
			continue
		}

		initialSecret := hkdf.Extract(crypto.SHA256.New, hdr.DestConnectionID, getSalt(hdr.Version))
		clientSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "client in", nil, crypto.SHA256.Size())
		key, err := NewInitialProtectionKey(clientSecret, hdr.Version)
		if err != nil {
			continue
		}
		// UnProtect decrypts in place. Own the packet so feeding a retransmission
		// or another analyzer the same datagram does not see mutated bytes.
		payload, err := NewPacketProtector(key).UnProtect(bytes.Clone(packet), offset, 2)
		if err != nil {
			continue
		}
		frames, err := extractCryptoFrames(bytes.NewReader(payload))
		if err != nil {
			continue
		}
		size := 0
		for _, f := range frames {
			size += len(f.Data)
		}
		if len(c.frames)+len(frames) > maxCryptoFrames || c.size+size > MaxCryptoStreamSize {
			return errors.New("CRYPTO reassembly limit exceeded")
		}
		c.dcid = hdr.DestConnectionID
		c.version = hdr.Version
		c.frames = append(c.frames, frames...)
		c.size += size
		found = true
	}
	if !found {
		return errors.New("no valid client Initial packet")
	}
	return nil
}

// Stream returns an owned copy of the contiguous start of the CRYPTO stream.
func (c *CryptoStream) Stream() []byte {
	return assembleCryptoFrames(c.frames)
}

// ReadCryptoPayload reads the contiguous CRYPTO prefix from a single datagram.
// Use CryptoStream when the ClientHello may span multiple datagrams.
func ReadCryptoPayload(packet []byte) ([]byte, error) {
	var c CryptoStream
	if err := c.Feed(packet); err != nil {
		return nil, err
	}
	data := c.Stream()
	if len(data) == 0 {
		return nil, errors.New("unable to assemble crypto frames")
	}
	return data, nil
}

const (
	paddingFrameType = 0x00
	pingFrameType    = 0x01
	cryptoFrameType  = 0x06
)

type cryptoFrame struct {
	Offset int64
	Data   []byte
}

func extractCryptoFrames(r *bytes.Reader) ([]cryptoFrame, error) {
	var frames []cryptoFrame
	for r.Len() > 0 {
		typ, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if typ == paddingFrameType || typ == pingFrameType {
			continue
		}
		if typ != cryptoFrameType {
			return nil, fmt.Errorf("encountered unexpected frame type: %d", typ)
		}
		var frame cryptoFrame
		offset, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		frame.Offset = int64(offset)
		dataLen, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if dataLen > uint64(r.Len()) {
			return nil, io.ErrUnexpectedEOF
		}
		if offset > MaxCryptoStreamSize || dataLen > MaxCryptoStreamSize-offset || len(frames) >= maxCryptoFrames {
			return nil, errors.New("CRYPTO frame limit exceeded")
		}
		frame.Data = make([]byte, int(dataLen))
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// assembleCryptoFrames returns the contiguous prefix, ignoring duplicate bytes
// in overlapping retransmissions and stopping at the first gap.
func assembleCryptoFrames(frames []cryptoFrame) []byte {
	slices.SortStableFunc(frames, func(a, b cryptoFrame) int { return cmp.Compare(a.Offset, b.Offset) })
	var data []byte
	for _, frame := range frames {
		n := int64(len(data))
		if frame.Offset > n {
			break
		}
		if end := frame.Offset + int64(len(frame.Data)); end > n {
			data = append(data, frame.Data[n-frame.Offset:]...)
		}
	}
	return data
}
