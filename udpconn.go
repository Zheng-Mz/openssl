package openssl

import (
	"errors"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/udp"
	"net"
)

func ListenUPD(network string, laddr *net.UDPAddr, ctx *Ctx) (net.Listener, error) {
	if ctx == nil {
		return nil, errors.New("no ssl context provided")
	}

	lc := udp.ListenConfig{
		AcceptFilter: func(packet []byte) bool {
			pkts, err := recordlayer.UnpackDatagram(packet)
			if err != nil || len(pkts) < 1 {
				return false
			}
			h := &recordlayer.Header{}
			if err := h.Unmarshal(pkts[0]); err != nil {
				return false
			}
			return h.ContentType == protocol.ContentTypeHandshake
		},
	}

	l, err := lc.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	return NewListener(l, ctx), nil
}