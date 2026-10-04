package udp

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/udp/internal/quic"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

const (
	quicInvalidCountThreshold = 4
	quicMaxClientPackets      = 8
)

var (
	_ analyzer.UDPAnalyzer = (*QUICAnalyzer)(nil)
	_ analyzer.UDPStream   = (*quicStream)(nil)
)

type QUICAnalyzer struct{}

func (a *QUICAnalyzer) Name() string {
	return "quic"
}

func (a *QUICAnalyzer) Limit() int {
	return 0
}

func (a *QUICAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &quicStream{logger: logger}
}

type quicStream struct {
	logger       analyzer.Logger
	invalidCount int
	packetCount  int
	crypto       quic.CryptoStream
}

func (s *quicStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	// minimal data size: protocol version (2 bytes) + random (32 bytes) +
	//   + session ID (1 byte) + cipher suites (4 bytes) +
	//   + compression methods (2 bytes) + no extensions
	const minDataSize = 41

	if rev {
		// Server packets can arrive between ClientHello fragments.
		return nil, false
	}

	s.packetCount++
	defer func() {
		if s.packetCount >= quicMaxClientPackets {
			done = true
		}
		if done {
			s.crypto = quic.CryptoStream{}
		}
	}()

	if err := s.crypto.Feed(data); err != nil {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}
	pl := s.crypto.Stream()
	if len(pl) < 4 {
		return nil, false
	}

	if pl[0] != internal.TypeClientHello {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize || chLen > quic.MaxCryptoStreamSize-4 {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	if len(pl)-4 < chLen {
		return nil, false
	}
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4 : 4+chLen]})
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

func (s *quicStream) Close(limited bool) *analyzer.PropUpdate {
	s.crypto = quic.CryptoStream{}
	return nil
}
