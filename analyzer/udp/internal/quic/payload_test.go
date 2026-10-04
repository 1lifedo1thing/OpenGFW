package quic

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

func TestAssembleCryptoFrames(t *testing.T) {
	for _, tt := range []struct {
		name   string
		frames []cryptoFrame
		want   string
	}{
		{"reordered", []cryptoFrame{{2, []byte("cd")}, {0, []byte("ab")}}, "abcd"},
		{"gap", []cryptoFrame{{0, []byte("ab")}, {3, []byte("d")}}, "ab"},
		{"missing start", []cryptoFrame{{2, []byte("cd")}}, ""},
		{"duplicate", []cryptoFrame{{0, []byte("ab")}, {0, []byte("ab")}, {2, []byte("cd")}}, "abcd"},
		{"overlap", []cryptoFrame{{0, []byte("abc")}, {1, []byte("bcde")}}, "abcde"},
		{"contained", []cryptoFrame{{0, []byte("abcd")}, {1, []byte("bc")}}, "abcd"},
		{"empty", nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := assembleCryptoFrames(tt.frames); string(got) != tt.want {
				t.Fatalf("assembled = %q, want %q", got, tt.want)
			}
		})
	}
}

func cryptoPayload(offset uint64, data []byte) []byte {
	b := quicvarint.Append(nil, cryptoFrameType)
	b = quicvarint.Append(b, offset)
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

// Protect a client Initial so tests exercise header protection and AEAD as well
// as reassembly, with both version-specific key labels and packet types.
func initialPacket(t testing.TB, version uint32, pn byte, payload []byte) []byte {
	t.Helper()
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	secret := hkdf.Extract(crypto.SHA256.New, dcid, getSalt(version))
	secret = hkdfExpandLabel(crypto.SHA256.New, secret, "client in", nil, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(secret, version)
	if err != nil {
		t.Fatal(err)
	}
	first := byte(0xc0)
	if version == V2 {
		first = 0xd0
	}
	header := binary.BigEndian.AppendUint32([]byte{first}, version)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0, 0) // Empty SCID and token.
	payload = append(bytes.Clone(payload), make([]byte, 32)...)
	header = quicvarint.Append(header, uint64(1+len(payload)+key.aead.Overhead()))
	pnOffset := len(header)
	header = append(header, pn)
	packet := key.aead.Seal(header, key.nonce(int64(pn)), payload, header)
	mask := key.headerProtection(packet[pnOffset+4 : pnOffset+4+16])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

func TestCryptoStream(t *testing.T) {
	for _, version := range []uint32{V1, V2} {
		t.Run(fmt.Sprintf("%08x", version), func(t *testing.T) {
			first := initialPacket(t, version, 0, cryptoPayload(2, []byte("cdef")))
			second := initialPacket(t, version, 1, cryptoPayload(0, []byte("abcd")))
			var c CryptoStream
			if err := c.Feed(first); err != nil {
				t.Fatal(err)
			}
			if len(c.Stream()) != 0 {
				t.Fatal("exposed a fragment before offset zero")
			}
			if err := c.Feed(second); err != nil || string(c.Stream()) != "abcdef" {
				t.Fatalf("reassembly: %q, %v", c.Stream(), err)
			}
			var coalesced CryptoStream
			if err := coalesced.Feed(bytes.Join([][]byte{first, second}, nil)); err != nil || string(coalesced.Stream()) != "abcdef" {
				t.Fatalf("coalesced reassembly: %q, %v", coalesced.Stream(), err)
			}
			// Handshake packets have a length but no token; skip them when
			// walking a datagram that also contains client Initial packets.
			handshakeType := byte(2)
			if version == V2 {
				handshakeType = 3
			}
			handshake := binary.BigEndian.AppendUint32([]byte{0xc0 | handshakeType<<4}, version)
			handshake = append(handshake, 0, 0, 1, 0) // Empty IDs, length 1, payload.
			var mixed CryptoStream
			if err := mixed.Feed(bytes.Join([][]byte{first, handshake, second}, nil)); err != nil || string(mixed.Stream()) != "abcdef" {
				t.Fatalf("non-Initial packet interrupted reassembly: %q, %v", mixed.Stream(), err)
			}
			for _, bad := range [][]byte{
				append([]byte{first[0] &^ 0x80}, first[1:]...),
				append([]byte{first[0], 0xff, 0xff, 0xff, 0xff}, first[5:]...),
			} {
				var invalid CryptoStream
				if err := invalid.Feed(bad); err == nil {
					t.Fatal("accepted a short header or unsupported version")
				}
			}
			// A damaged packet must not bind the connection or retain fragments.
			bad := bytes.Clone(first)
			bad[len(bad)-1] ^= 1
			var corrupt CryptoStream
			if err := corrupt.Feed(bad); err == nil || corrupt.dcid != nil || len(corrupt.frames) != 0 {
				t.Fatal("accepted an unauthenticated packet")
			}
			for n := 0; n < len(first); n++ {
				var truncated CryptoStream
				if err := truncated.Feed(first[:n]); err == nil {
					t.Fatalf("accepted packet truncated to %d bytes", n)
				}
			}
		})
	}
}

func TestCryptoFrameLimits(t *testing.T) {
	for _, payload := range [][]byte{
		quicvarint.Append(cryptoPayload(0, nil)[:2], 1<<40),
		cryptoPayload(MaxCryptoStreamSize, []byte{1}),
		cryptoPayload(1<<40, nil),
		bytes.Repeat(cryptoPayload(0, nil), maxCryptoFrames+1),
	} {
		if _, err := extractCryptoFrames(bytes.NewReader(payload)); err == nil {
			t.Fatal("accepted oversized or truncated CRYPTO frame")
		}
	}
	var c CryptoStream
	packet := initialPacket(t, V1, 0, cryptoPayload(0, bytes.Repeat([]byte{1}, MaxCryptoStreamSize/2)))
	for range 2 {
		if err := c.Feed(packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Feed(packet); err == nil || c.size > MaxCryptoStreamSize {
		t.Fatal("failed to bound retained fragments")
	}
}

func FuzzCryptoStream(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add(initialPacket(f, V1, 0, cryptoPayload(0, []byte("ClientHello"))))
	f.Add(initialPacket(f, V2, 0, cryptoPayload(2, []byte("fragment"))))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c CryptoStream
		_ = c.Feed(data)
		_ = c.Stream()
	})
}
