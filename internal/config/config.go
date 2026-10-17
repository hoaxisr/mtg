package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/web"
)

type Optional struct {
	Enabled TypeBool `json:"enabled"`
}

type ListConfig struct {
	Optional

	DownloadConcurrency TypeConcurrency    `json:"downloadConcurrency"`
	URLs                []TypeBlocklistURI `json:"urls"`
	UpdateEach          TypeDuration       `json:"updateEach"`
}

type Config struct {
	Debug                       TypeBool        `json:"debug"`
	AllowFallbackOnUnknownDC    TypeBool        `json:"allowFallbackOnUnknownDc"`
	Secret                      mtglib.Secret   `json:"secret"`
	BindTo                      TypeHostPort    `json:"bindTo"`
	ProxyProtocolListener       TypeBool        `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP    `json:"preferIp"`
	AutoUpdate                  TypeBool        `json:"autoUpdate"`
	DomainFrontingPort          TypePort        `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP          `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool        `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration    `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency `json:"concurrency"`
	PublicIPv4                  TypeIP          `json:"publicIpv4"`
	PublicIPv6                  TypeIP          `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			Optional

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL  `json:"urls"`
			Repeats    TypeConcurrency `json:"repeats_per_raid"`
			UpdateEach TypeDuration    `json:"raid_each"`
			DRS        TypeBool        `json:"drs"`
		} `json:"doppelganger"`
	} `json:"defense"`
	Network struct {
		Timeout struct {
			TCP       TypeDuration `json:"tcp"`
			HTTP      TypeDuration `json:"http"`
			Idle      TypeDuration `json:"idle"`
			Handshake TypeDuration `json:"handshake"`
		} `json:"timeout"`
		KeepAlive struct {
			Disabled TypeBool        `json:"disabled"`
			Idle     TypeDuration    `json:"idle"`
			Interval TypeDuration    `json:"interval"`
			Count    TypeConcurrency `json:"count"`
		} `json:"keepAlive"`
		DOHIP           TypeIP         `json:"dohIp"`
		DNS             TypeDNSURI     `json:"dns"`
		Proxies         []TypeProxyURL `json:"proxies"`
		TCPNotSentLowat TypeBytes      `json:"tcpNotSentLowat"`
	} `json:"network"`
	Stats struct {
		StatsD struct {
			Optional

			Address      TypeHostPort        `json:"address"`
			MetricPrefix TypeMetricPrefix    `json:"metricPrefix"`
			TagFormat    TypeStatsdTagFormat `json:"tagFormat"`
		} `json:"statsd"`
		Prometheus struct {
			Optional

			BindTo       TypeHostPort     `json:"bindTo"`
			HTTPPath     TypeHTTPPath     `json:"httpPath"`
			MetricPrefix TypeMetricPrefix `json:"metricPrefix"`
		} `json:"prometheus"`
	} `json:"stats"`
	Web struct {
		Optional

		BindTo         TypeHostPort  `json:"bindTo"`
		Hostname       TypeHost      `json:"hostname"`
		PublicUpstream TypeHTTPURL   `json:"publicUpstream"`
		PublicDir      TypeDirectory `json:"publicDir"`
		TrustedProxies []TypeCIDR    `json:"trustedProxies"`
		TokenKey       TypeTokenKey  `json:"tokenKey"`
		Limits         struct {
			MaxSessions          TypeCount `json:"maxSessions"`
			MaxSessionsPerIP     TypeCount `json:"maxSessionsPerIp"`
			MaxStreams           TypeCount `json:"maxStreams"`
			MaxStreamsPerSession TypeCount `json:"maxStreamsPerSession"`

			NewSessionsPerMinute TypeCount `json:"newSessionsPerMinute"`
			NewSessionsBurst     TypeCount `json:"newSessionsBurst"`
			NewStreamsPerMinute  TypeCount `json:"newStreamsPerMinute"`
			NewStreamsBurst      TypeCount `json:"newStreamsBurst"`

			MaxBootstraps          TypeCount `json:"maxBootstraps"`
			MaxBootstrapsPerIP     TypeCount `json:"maxBootstrapsPerIp"`
			NewBootstrapsPerMinute TypeCount `json:"newBootstrapsPerMinute"`
			NewBootstrapsBurst     TypeCount `json:"newBootstrapsBurst"`

			MaxPendingPerSession TypeBytes `json:"maxPendingPerSession"`
			MaxPendingGlobal     TypeBytes `json:"maxPendingGlobal"`
			CarrierBatchBytes    TypeBytes `json:"carrierBatchBytes"`
			MaxBodyBytes         TypeBytes `json:"maxBodyBytes"`
			MaxFramePayload      TypeBytes `json:"maxFramePayload"`

			MaxPendingItemsPerSession TypeCount `json:"maxPendingItemsPerSession"`
			MaxPendingItemsGlobal     TypeCount `json:"maxPendingItemsGlobal"`
			MaxClosedStreamIDs        TypeCount `json:"maxClosedStreamIds"`
		} `json:"limits"`
		Timeouts struct {
			LongPoll          TypeDuration `json:"longPoll"`
			ReconnectGrace    TypeDuration `json:"reconnectGrace"`
			BootstrapLifetime TypeDuration `json:"bootstrapLifetime"`
			Shutdown          TypeDuration `json:"shutdown"`
		} `json:"timeouts"`
	} `json:"web"`
}

func (c *Config) GetConcurrency(defaultValue uint) uint {
	if concurrency := c.Concurrency.Get(0); concurrency != 0 {
		return concurrency
	}
	return c.Concurrency.Get(defaultValue)
}

func (c *Config) GetDNS() *url.URL {
	var dohURL *url.URL

	if dohIP := c.Network.DOHIP.Get(nil); dohIP != nil {
		dohURL, _ = url.Parse("https://" + dohIP.String())
	}

	return c.Network.DNS.Get(dohURL)
}

func (c *Config) GetDomainFrontingPort(defaultValue uint) uint {
	if port := c.DomainFronting.Port.Get(0); port != 0 {
		return port
	}
	return c.DomainFrontingPort.Get(defaultValue)
}

func (c *Config) GetDomainFrontingHost() string {
	return c.DomainFronting.Host.Get("")
}

func (c *Config) GetDomainFrontingProxyProtocol(defaultValue bool) bool {
	return c.DomainFronting.ProxyProtocol.Get(false) || c.DomainFrontingProxyProtocol.Get(defaultValue)
}

// GetWebLimits returns web proxy limits: defaults overlaid with the values
// that are set in the config.
func (c *Config) GetWebLimits() web.Limits {
	l := web.DefaultLimits()
	cl := &c.Web.Limits

	count := func(dst *int, v TypeCount) {
		*dst = int(v.Get(uint(*dst)))
	}
	size := func(dst *int, v TypeBytes) {
		*dst = int(v.Get(uint(*dst)))
	}
	size64 := func(dst *int64, v TypeBytes) {
		*dst = int64(v.Get(uint(*dst)))
	}

	count(&l.MaxSessions, cl.MaxSessions)
	count(&l.MaxSessionsPerIP, cl.MaxSessionsPerIP)
	count(&l.MaxStreams, cl.MaxStreams)
	count(&l.MaxStreamsPerSession, cl.MaxStreamsPerSession)

	count(&l.NewSessionsPerMinute, cl.NewSessionsPerMinute)
	count(&l.NewSessionsBurst, cl.NewSessionsBurst)
	count(&l.NewStreamsPerMinute, cl.NewStreamsPerMinute)
	count(&l.NewStreamsBurst, cl.NewStreamsBurst)

	count(&l.MaxBootstraps, cl.MaxBootstraps)
	count(&l.MaxBootstrapsPerIP, cl.MaxBootstrapsPerIP)
	count(&l.NewBootstrapsPerMinute, cl.NewBootstrapsPerMinute)
	count(&l.NewBootstrapsBurst, cl.NewBootstrapsBurst)

	size64(&l.MaxPendingPerSession, cl.MaxPendingPerSession)
	size64(&l.MaxPendingGlobal, cl.MaxPendingGlobal)

	count(&l.MaxPendingItemsPerSession, cl.MaxPendingItemsPerSession)
	count(&l.MaxPendingItemsGlobal, cl.MaxPendingItemsGlobal)

	size(&l.CarrierBatchBytes, cl.CarrierBatchBytes)
	size(&l.MaxBodyBytes, cl.MaxBodyBytes)
	size(&l.MaxFramePayload, cl.MaxFramePayload)
	count(&l.MaxClosedStreamIDs, cl.MaxClosedStreamIDs)

	return l
}

// GetWebTimeouts returns web proxy timeouts: defaults overlaid with the
// values that are set in the config.
func (c *Config) GetWebTimeouts() web.Timeouts {
	t := web.DefaultTimeouts()
	ct := &c.Web.Timeouts

	t.LongPoll = ct.LongPoll.Get(t.LongPoll)
	t.ReconnectGrace = ct.ReconnectGrace.Get(t.ReconnectGrace)
	t.BootstrapLifetime = ct.BootstrapLifetime.Get(t.BootstrapLifetime)
	t.Shutdown = ct.Shutdown.Get(t.Shutdown)

	return t
}

// GetWebTrustedProxies returns trusted proxy networks or nil if none are
// configured.
func (c *Config) GetWebTrustedProxies() []netip.Prefix {
	if len(c.Web.TrustedProxies) == 0 {
		return nil
	}

	prefixes := make([]netip.Prefix, 0, len(c.Web.TrustedProxies))

	for _, v := range c.Web.TrustedProxies {
		prefixes = append(prefixes, v.Value)
	}

	return prefixes
}

func (c *Config) validateWeb() error {
	if c.Web.BindTo.Get("") == "" {
		return fmt.Errorf("incorrect web.bind-to parameter %s", c.Web.BindTo.String())
	}

	hostname := c.Web.Hostname.Get("")
	if hostname == "" {
		return fmt.Errorf("web.hostname is required")
	}

	if err := web.ValidateHostname(hostname); err != nil {
		return fmt.Errorf("incorrect web.hostname: %w", err)
	}

	hasUpstream := c.Web.PublicUpstream.Value != nil
	hasDir := c.Web.PublicDir.Get("") != ""

	if hasUpstream == hasDir {
		return fmt.Errorf("exactly one of web.public-upstream and web.public-dir has to be set")
	}

	if err := web.ValidateLimits(c.GetWebLimits()); err != nil {
		return fmt.Errorf("incorrect [web.limits]: %w", err)
	}

	if err := web.ValidateTimeouts(c.GetWebTimeouts()); err != nil {
		return fmt.Errorf("incorrect [web.timeouts]: %w", err)
	}

	return nil
}

func (c *Config) Validate() error {
	if !c.Secret.Valid() {
		return fmt.Errorf("invalid secret %s", c.Secret.String())
	}

	if c.BindTo.Get("") == "" {
		return fmt.Errorf("incorrect bind-to parameter %s", c.BindTo.String())
	}

	if c.Web.Enabled.Get(false) {
		return c.validateWeb()
	}

	return nil
}

func (c *Config) String() string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}
