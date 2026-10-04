package udp

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
)

func TestQuicStreamParsing_ClientHello(t *testing.T) {
	// example packet taken from <https://quic.xargs.org/#client-initial-packet/annotated>
	clientHello := make([]byte, 1200)
	clientInitial := []byte{
		0xcd, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x00, 0x41, 0x03, 0x98,
		0x1c, 0x36, 0xa7, 0xed, 0x78, 0x71, 0x6b, 0xe9, 0x71, 0x1b, 0xa4, 0x98,
		0xb7, 0xed, 0x86, 0x84, 0x43, 0xbb, 0x2e, 0x0c, 0x51, 0x4d, 0x4d, 0x84,
		0x8e, 0xad, 0xcc, 0x7a, 0x00, 0xd2, 0x5c, 0xe9, 0xf9, 0xaf, 0xa4, 0x83,
		0x97, 0x80, 0x88, 0xde, 0x83, 0x6b, 0xe6, 0x8c, 0x0b, 0x32, 0xa2, 0x45,
		0x95, 0xd7, 0x81, 0x3e, 0xa5, 0x41, 0x4a, 0x91, 0x99, 0x32, 0x9a, 0x6d,
		0x9f, 0x7f, 0x76, 0x0d, 0xd8, 0xbb, 0x24, 0x9b, 0xf3, 0xf5, 0x3d, 0x9a,
		0x77, 0xfb, 0xb7, 0xb3, 0x95, 0xb8, 0xd6, 0x6d, 0x78, 0x79, 0xa5, 0x1f,
		0xe5, 0x9e, 0xf9, 0x60, 0x1f, 0x79, 0x99, 0x8e, 0xb3, 0x56, 0x8e, 0x1f,
		0xdc, 0x78, 0x9f, 0x64, 0x0a, 0xca, 0xb3, 0x85, 0x8a, 0x82, 0xef, 0x29,
		0x30, 0xfa, 0x5c, 0xe1, 0x4b, 0x5b, 0x9e, 0xa0, 0xbd, 0xb2, 0x9f, 0x45,
		0x72, 0xda, 0x85, 0xaa, 0x3d, 0xef, 0x39, 0xb7, 0xef, 0xaf, 0xff, 0xa0,
		0x74, 0xb9, 0x26, 0x70, 0x70, 0xd5, 0x0b, 0x5d, 0x07, 0x84, 0x2e, 0x49,
		0xbb, 0xa3, 0xbc, 0x78, 0x7f, 0xf2, 0x95, 0xd6, 0xae, 0x3b, 0x51, 0x43,
		0x05, 0xf1, 0x02, 0xaf, 0xe5, 0xa0, 0x47, 0xb3, 0xfb, 0x4c, 0x99, 0xeb,
		0x92, 0xa2, 0x74, 0xd2, 0x44, 0xd6, 0x04, 0x92, 0xc0, 0xe2, 0xe6, 0xe2,
		0x12, 0xce, 0xf0, 0xf9, 0xe3, 0xf6, 0x2e, 0xfd, 0x09, 0x55, 0xe7, 0x1c,
		0x76, 0x8a, 0xa6, 0xbb, 0x3c, 0xd8, 0x0b, 0xbb, 0x37, 0x55, 0xc8, 0xb7,
		0xeb, 0xee, 0x32, 0x71, 0x2f, 0x40, 0xf2, 0x24, 0x51, 0x19, 0x48, 0x70,
		0x21, 0xb4, 0xb8, 0x4e, 0x15, 0x65, 0xe3, 0xca, 0x31, 0x96, 0x7a, 0xc8,
		0x60, 0x4d, 0x40, 0x32, 0x17, 0x0d, 0xec, 0x28, 0x0a, 0xee, 0xfa, 0x09,
		0x5d, 0x08, 0xb3, 0xb7, 0x24, 0x1e, 0xf6, 0x64, 0x6a, 0x6c, 0x86, 0xe5,
		0xc6, 0x2c, 0xe0, 0x8b, 0xe0, 0x99,
	}
	copy(clientHello, clientInitial)

	want := analyzer.PropMap{
		"alpn":               []string{"ping/1.0"},
		"ciphers":            []uint16{4865, 4866, 4867},
		"compression":        []uint8{0},
		"random":             []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		"session":            []uint8{},
		"sni":                "example.ulfheim.net",
		"supported_versions": []uint16{772},
		"version":            uint16(771),
	}

	s := quicStream{}
	u, _ := s.Feed(false, clientHello)
	got := u.M.Get("req")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%d B parsed = %v, want %v", len(clientHello), got, want)
	}
}

// These first-flight captures come from Hysteria's extras/sniff/testdata.
func TestQuicStreamFragmentedClientHello(t *testing.T) {
	read := func(name string, count int) [][]byte {
		t.Helper()
		packets := make([][]byte, count)
		for i := range packets {
			var err error
			packets[i], err = os.ReadFile(fmt.Sprintf("testdata/quic-%s-%d.bin", name, i))
			if err != nil {
				t.Fatal(err)
			}
		}
		return packets
	}
	chrome := read("chrome153", 3)
	firefox := read("firefox153esr", 2)
	curl := read("curl8.14-openssl3.5", 2)
	for _, tt := range []struct {
		name    string
		packets [][]byte
		sni     string
	}{
		{"Chrome", chrome[:2], "chrome.sniff.test"},
		{"Chrome reordered", [][]byte{chrome[1], chrome[0]}, "chrome.sniff.test"},
		{"Chrome retransmitted", [][]byte{chrome[1], chrome[2]}, "chrome.sniff.test"},
		{"Chrome duplicates", append(slices.Repeat([][]byte{chrome[0]}, 6), chrome[1]), "chrome.sniff.test"},
		{"Chrome coalesced", [][]byte{bytes.Join(chrome[:2], nil)}, "chrome.sniff.test"},
		{"Firefox", firefox, "firefox.sniff.test"},
		{"Firefox reordered", [][]byte{firefox[1], firefox[0]}, "firefox.sniff.test"},
		{"curl", curl, "curl.sniff.test"},
		{"quiche", read("quiche", 3), "quiche.sniff.test"},
		{"ngtcp2", read("ngtcp2-1.11", 1), "ngtcp2.sniff.test"},
		{"aioquic", read("aioquic1.2", 1), "aioquic.sniff.test"},
		{"Other connections", [][]byte{chrome[0], firefox[1], curl[1], chrome[1]}, "chrome.sniff.test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := (&QUICAnalyzer{}).NewUDP(analyzer.UDPInfo{}, nil)
			for i, packet := range tt.packets {
				before := bytes.Clone(packet)
				u, done := s.Feed(false, packet)
				if !bytes.Equal(packet, before) {
					t.Fatal("Feed modified the datagram")
				}
				if i < len(tt.packets)-1 {
					if u != nil || done {
						t.Fatalf("packet %d: prematurely completed: %v, %v", i, u, done)
					}
					// Server traffic must not exhaust the invalid-packet budget.
					for range quicInvalidCountThreshold {
						if u, done := s.Feed(true, []byte{0}); u != nil || done {
							t.Fatal("server traffic terminated reassembly")
						}
					}
					continue
				}
				if !done || u == nil || u.Type != analyzer.PropUpdateMerge || u.M.Get("req.sni") != tt.sni {
					t.Fatalf("got %v, done %v; want SNI %s", u, done, tt.sni)
				}
			}
		})
	}

	t.Run("Incomplete packet budget", func(t *testing.T) {
		var s quicStream
		for i := 1; i <= quicMaxClientPackets; i++ {
			u, done := s.Feed(false, chrome[0])
			if u != nil || done != (i == quicMaxClientPackets) || s.invalidCount != 0 {
				t.Fatalf("packet %d: update %v, done %v, invalid %d", i, u, done, s.invalidCount)
			}
		}
		if len(s.crypto.Stream()) != 0 {
			t.Fatal("completed analyzer retained fragments")
		}
	})
	t.Run("Close releases fragments", func(t *testing.T) {
		var s quicStream
		s.Feed(false, chrome[0])
		s.Close(false)
		if !reflect.DeepEqual(s.crypto, (quicStream{}).crypto) {
			t.Fatal("Close retained reassembly state")
		}
	})
}

func TestQuicStreamInvalidPackets(t *testing.T) {
	var s quicStream
	for i := 1; i <= quicInvalidCountThreshold; i++ {
		u, done := s.Feed(false, []byte("not QUIC"))
		if u != nil || done != (i == quicInvalidCountThreshold) {
			t.Fatalf("packet %d: update %v, done %v", i, u, done)
		}
	}
}
