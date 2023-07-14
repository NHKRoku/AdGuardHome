package client_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/stretchr/testify/assert"
)

func TestEmptyAddrProc(t *testing.T) {
	t.Parallel()

	p := client.EmptyAddrProc{}

	assert.NotPanics(t, func() {
		p.Process(testIP)
	})

	assert.NotPanics(t, func() {
		err := p.Close()
		assert.NoError(t, err)
	})
}

func TestDefaultAddrProc_Process_rDNS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		rdnsErr error
		name    string
		host    string
		wantUpd bool
	}{{
		rdnsErr: nil,
		name:    "success",
		host:    testHost,
		wantUpd: true,
	}, {
		rdnsErr: nil,
		name:    "no_host",
		host:    "",
		wantUpd: false,
	}, {
		rdnsErr: errors.Error("rdns error"),
		name:    "rdns_error",
		host:    "",
		wantUpd: false,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			updIPCh := make(chan netip.Addr, 1)
			updHostCh := make(chan string, 1)
			updInfoCh := make(chan *whois.Info, 1)

			p := client.NewDefaultAddrProc(&client.DefaultAddrProcConfig{
				DialContext: func(_ context.Context, _, _ string) (conn net.Conn, err error) {
					panic("not implemented")
				},
				Exchanger: &aghtest.Exchanger{
					OnExchange: func(ip netip.Addr) (host string, err error) {
						return tc.host, tc.rdnsErr
					},
				},
				PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
				AddressUpdater: &aghtest.AddressUpdater{
					OnUpdateAddress: func(ip netip.Addr, host string, info *whois.Info) {
						updIPCh <- ip
						updHostCh <- host
						updInfoCh <- info
					},
				},
				UseRDNS:        true,
				UsePrivateRDNS: true,
				UseWHOIS:       false,
			})
			testutil.CleanupAndRequireSuccess(t, p.Close)

			p.Process(testIP)

			if tc.wantUpd {
				gotIP, _ := testutil.RequireReceive(t, updIPCh, testTimeout)
				assert.Equal(t, testIP, gotIP)

				gotHost, _ := testutil.RequireReceive(t, updHostCh, testTimeout)
				assert.Equal(t, tc.host, gotHost)

				gotInfo, _ := testutil.RequireReceive(t, updInfoCh, testTimeout)
				assert.Nil(t, gotInfo)
			}
		})
	}
}

func TestDefaultAddrProc_Process_WHOIS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantInfo *whois.Info
		exchErr  error
		name     string
		wantUpd  bool
	}{{
		wantInfo: &whois.Info{
			City: testWHOISCity,
		},
		exchErr: nil,
		name:    "success",
		wantUpd: true,
	}, {
		wantInfo: nil,
		exchErr:  nil,
		name:     "no_info",
		wantUpd:  false,
	}, {
		wantInfo: nil,
		exchErr:  errors.Error("whois error"),
		name:     "whois_error",
		wantUpd:  false,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			updIPCh := make(chan netip.Addr, 1)
			updHostCh := make(chan string, 1)
			updInfoCh := make(chan *whois.Info, 1)

			whoisConn := &fakenet.Conn{
				OnClose: func() (err error) { return nil },
				OnRead: func(b []byte) (n int, err error) {
					if tc.wantInfo == nil {
						return 0, tc.exchErr
					}

					data := "city: " + tc.wantInfo.City + "\n"
					copy(b, data)

					return len(data), io.EOF
				},
				OnSetDeadline: func(_ time.Time) (err error) { return nil },
				OnWrite:       func(b []byte) (n int, err error) { return len(b), nil },
			}

			p := client.NewDefaultAddrProc(&client.DefaultAddrProcConfig{
				DialContext: func(_ context.Context, _, _ string) (conn net.Conn, err error) {
					return whoisConn, nil
				},
				Exchanger: &aghtest.Exchanger{
					OnExchange: func(_ netip.Addr) (host string, err error) {
						panic("not implemented")
					},
				},
				PrivateSubnets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
				AddressUpdater: &aghtest.AddressUpdater{
					OnUpdateAddress: func(ip netip.Addr, host string, info *whois.Info) {
						updIPCh <- ip
						updHostCh <- host
						updInfoCh <- info
					},
				},
				UseRDNS:        false,
				UsePrivateRDNS: false,
				UseWHOIS:       true,
			})
			testutil.CleanupAndRequireSuccess(t, p.Close)

			p.Process(testIP)

			if tc.wantUpd {
				gotIP, _ := testutil.RequireReceive(t, updIPCh, testTimeout)
				assert.Equal(t, testIP, gotIP)

				gotHost, _ := testutil.RequireReceive(t, updHostCh, testTimeout)
				assert.Empty(t, gotHost)

				gotInfo, _ := testutil.RequireReceive(t, updInfoCh, testTimeout)
				assert.Equal(t, tc.wantInfo, gotInfo)
			}
		})
	}
}

func TestDefaultAddrProc_Close(t *testing.T) {
	t.Parallel()

	p := client.NewDefaultAddrProc(&client.DefaultAddrProcConfig{})

	err := p.Close()
	assert.NoError(t, err)

	err = p.Close()
	assert.ErrorIs(t, err, net.ErrClosed)
}
