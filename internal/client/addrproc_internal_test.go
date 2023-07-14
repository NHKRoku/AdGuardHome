package client

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/require"
)

func TestDefaultAddrProc_shouldResolve(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		ip             netip.Addr
		want           require.BoolAssertionFunc
		name           string
		useRDNS        bool
		usePrivateRDNS bool
	}{{
		name:           "default",
		ip:             netip.MustParseAddr("1.1.1.1"),
		want:           require.True,
		useRDNS:        true,
		usePrivateRDNS: true,
	}, {
		name:           "no_rdns",
		ip:             netip.MustParseAddr("1.1.1.1"),
		want:           require.False,
		useRDNS:        false,
		usePrivateRDNS: true,
	}, {
		name:           "loopback",
		ip:             netip.MustParseAddr("127.0.0.1"),
		want:           require.False,
		useRDNS:        true,
		usePrivateRDNS: true,
	}, {
		name:           "private_resolve",
		ip:             netip.MustParseAddr("192.168.0.1"),
		want:           require.True,
		useRDNS:        true,
		usePrivateRDNS: true,
	}, {
		name:           "private_no_resolve",
		ip:             netip.MustParseAddr("192.168.0.1"),
		want:           require.False,
		useRDNS:        true,
		usePrivateRDNS: false,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &DefaultAddrProc{
				privateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
				usePrivateRDNS: tc.usePrivateRDNS,
				useRDNS:        tc.useRDNS,
			}

			ok := p.shouldResolve(tc.ip)
			tc.want(t, ok)
		})
	}
}
