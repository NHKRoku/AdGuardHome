package client

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// AddressProcessor is the interface for types that can process clients.
type AddressProcessor interface {
	Process(ip netip.Addr)
	Close() (err error)
}

// EmptyAddrProc is an [AddressProcessor] that does nothing.
type EmptyAddrProc struct{}

var _ AddressProcessor = EmptyAddrProc{}

// Process implements the [AddressProcessor] interface for EmptyAddrProc.
func (p EmptyAddrProc) Process(ip netip.Addr) {}

// Close implements the [AddressProcessor] interface for EmptyAddrProc.
func (p EmptyAddrProc) Close() (err error) { return nil }

// DefaultAddrProc processes incoming client addresses with rDNS and WHOIS, if
// configured, and updates that information in a client storage.
type DefaultAddrProc struct {
	clientIPs      chan netip.Addr
	closeOnce      *sync.Once
	rdns           rdns.Interface
	addrUpdater    AddressUpdater
	whois          whois.Interface
	privateSubnets netutil.SubnetSet
	useRDNS        bool
	usePrivateRDNS bool
	useWHOIS       bool
}

// AddressUpdater is the interface for storages of DNS clients that can update
// information about them.
//
// TODO(a.garipov): Consider using the actual client storage once it is moved
// into this package.
type AddressUpdater interface {
	// UpdateAddress updates information about an IP address, setting host (if
	// not empty) and WHOIS information (if not nil).
	UpdateAddress(ip netip.Addr, host string, info *whois.Info)
}

// DefaultAddrProcConfig is the configuration structure for address processors.
type DefaultAddrProcConfig struct {
	// DialContext is used to create TCP connections to WHOIS servers.
	DialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// Exchanger is used to perform rDNS queries.
	Exchanger rdns.Exchanger

	// PrivateSubnets are used to determine if an incoming IP address is
	// private.
	PrivateSubnets netutil.SubnetSet

	// AddressUpdater is used to update client information.
	AddressUpdater AddressUpdater

	// InitialAddresses are the addresses that are queued for processing
	// immediately by [NewDefaultAddrProc].
	InitialAddresses []netip.Addr

	// UseRDNS, if true, enables resolving of client IP addresses using reverse
	// DNS.
	UseRDNS bool

	// UsePrivateRDNS, if true, enables resolving of private client IP addresses
	// using reverse DNS.  See [DefaultAddrProcConfig.PrivateSubnets].
	UsePrivateRDNS bool

	// UseRDNS, if true, enables resolving of client IP addresses using WHOIS.
	UseWHOIS bool
}

const (
	// defaultQueueSize is the size of queue of IPs for rDNS and WHOIS
	// processing.
	defaultQueueSize = 255

	// defaultCacheSize is the maximum size of the cache for rDNS and WHOIS
	// processing.  It must be greater than zero.
	defaultCacheSize = 10_000

	// defaultIPTTL is the Time to Live duration for IP addresses cached by
	// rDNS and WHOIS.
	defaultIPTTL = 1 * time.Hour
)

// NewDefaultAddrProc returns a new running client address processor.  c must
// not be nil.
func NewDefaultAddrProc(c *DefaultAddrProcConfig) (p *DefaultAddrProc) {
	p = &DefaultAddrProc{
		clientIPs:      make(chan netip.Addr, defaultQueueSize),
		closeOnce:      &sync.Once{},
		rdns:           &rdns.Empty{},
		addrUpdater:    c.AddressUpdater,
		whois:          &whois.Empty{},
		privateSubnets: c.PrivateSubnets,
		usePrivateRDNS: c.UsePrivateRDNS,
		useRDNS:        c.UseRDNS,
		useWHOIS:       c.UseWHOIS,
	}

	if p.useRDNS {
		p.rdns = rdns.New(&rdns.Config{
			Exchanger: c.Exchanger,
			CacheSize: defaultCacheSize,
			CacheTTL:  defaultIPTTL,
		})
	}

	if p.useWHOIS {
		// TODO(s.chzhen):  Consider making configurable.
		const (
			// defaultTimeout is the timeout for WHOIS requests.
			defaultTimeout = 5 * time.Second

			// defaultMaxConnReadSize is an upper limit in bytes for reading from a
			// net.Conn.
			defaultMaxConnReadSize = 64 * 1024

			// defaultMaxRedirects is the maximum redirects count.
			defaultMaxRedirects = 5

			// defaultMaxInfoLen is the maximum length of whois.Info fields.
			defaultMaxInfoLen = 250
		)

		p.whois = whois.New(&whois.Config{
			DialContext:     c.DialContext,
			ServerAddr:      whois.DefaultServer,
			Port:            whois.DefaultPort,
			Timeout:         defaultTimeout,
			CacheSize:       defaultCacheSize,
			MaxConnReadSize: defaultMaxConnReadSize,
			MaxRedirects:    defaultMaxRedirects,
			MaxInfoLen:      defaultMaxInfoLen,
			CacheTTL:        defaultIPTTL,
		})
	}

	go p.process()

	for _, ip := range c.InitialAddresses {
		p.Process(ip)
	}

	return p
}

var _ AddressProcessor = (*DefaultAddrProc)(nil)

// Process implements the [AddressProcessor] interface for *DefaultAddrProc.
func (p *DefaultAddrProc) Process(ip netip.Addr) {
	select {
	case p.clientIPs <- ip:
		// Go on.
	default:
		log.Debug("clients: ip channel is full; len: %d", len(p.clientIPs))
	}
}

// process processes the incoming client IP-address information.  It is intended
// to be used as a goroutine.  Once clientIPs is closed, process exits.
func (p *DefaultAddrProc) process() {
	defer log.OnPanic("addrProcessor.process")

	log.Info("clients: processing addresses")

	for ip := range p.clientIPs {
		host := p.processRDNS(ip)
		info := p.processWHOIS(ip)

		p.addrUpdater.UpdateAddress(ip, host, info)
	}

	log.Info("clients: finished processing addresses")
}

// processRDNS resolves the clients' IP addresses using reverse DNS.  host is
// empty if there were errors or if the information hasn't changed.
func (p *DefaultAddrProc) processRDNS(ip netip.Addr) (host string) {
	start := time.Now()
	log.Debug("clients: processing %s with rdns", ip)
	defer func() {
		log.Debug("clients: finished processing %s with rdns in %s", ip, time.Since(start))
	}()

	ok := p.shouldResolve(ip)
	if !ok {
		return
	}

	host, changed := p.rdns.Process(ip)
	if !changed {
		host = ""
	}

	return host
}

// shouldResolve returns false if ip is a loopback address, or ip is private and
// resolving of private addresses is disabled.
func (p *DefaultAddrProc) shouldResolve(ip netip.Addr) (ok bool) {
	if ip.IsLoopback() {
		return false
	}

	isPrivate := p.privateSubnets.Contains(ip.AsSlice())

	return p.useRDNS &&
		(p.usePrivateRDNS || !isPrivate)
}

// processWHOIS looks up the information about clients' IP addresses in the
// WHOIS databases.  info is nil if there were errors or if the information
// hasn't changed.
func (p *DefaultAddrProc) processWHOIS(ip netip.Addr) (info *whois.Info) {
	start := time.Now()
	log.Debug("clients: processing %s with whois", ip)
	defer func() {
		log.Debug("clients: finished processing %s with whois in %s", ip, time.Since(start))
	}()

	// TODO(s.chzhen):  Move the timeout logic from WHOIS configuration to the
	// context.
	info, changed := p.whois.Process(context.Background(), ip)
	if !changed {
		info = nil
	}

	return info
}

// Close implements the [AddressProcessor] interface for *DefaultAddrProc.
func (p *DefaultAddrProc) Close() (err error) {
	closedNow := false
	p.closeOnce.Do(func() {
		close(p.clientIPs)
		closedNow = true
	})

	if !closedNow {
		return net.ErrClosed
	}

	return nil
}
