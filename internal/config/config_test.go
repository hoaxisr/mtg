package config_test

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/9seconds/mtg/v2/mtglib/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) ReadConfig(filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	suite.NoError(err)

	return data
}

func (suite *ConfigTestSuite) TestExampleConfigParses() {
	data, err := os.ReadFile("../../example.config.toml")
	suite.Require().NoError(err)

	conf, err := config.Parse(data)
	suite.Require().NoError(err)
	suite.NoError(conf.Validate())
	suite.False(conf.Web.Enabled.Get(false))
}

func (suite *ConfigTestSuite) TestParseEmpty() {
	_, err := config.Parse([]byte{})
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseBrokenToml() {
	_, err := config.Parse(suite.ReadConfig("broken.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseOnlySecret() {
	_, err := config.Parse(suite.ReadConfig("only_secret.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseMinimalConfig() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Equal("7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t", conf.Secret.Base64())
	suite.Equal("0.0.0.0:3128", conf.BindTo.String())
}

func (suite *ConfigTestSuite) TestParsePublicIP() {
	conf, err := config.Parse(suite.ReadConfig("public_ip.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Equal("2001:db8::1", conf.PublicIPv6.Get(nil).String())
}

func (suite *ConfigTestSuite) TestParsePublicIPv4Only() {
	conf, err := config.Parse(suite.ReadConfig("public_ip_v4_only.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestParsePublicIPInvalid() {
	_, err := config.Parse(suite.ReadConfig("public_ip_invalid.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParsePublicIPNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Nil(conf.PublicIPv4.Get(nil))
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestString() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NotEmpty(conf.String())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredWhenHostSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)

	suite.NoError(conf.DomainFronting.Host.Set("fronting-backend"))
	suite.NoError(conf.DomainFronting.IP.Set("10.0.0.10"))
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostAcceptsLiteralIP() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("10.0.0.1", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	// Deprecated [domain-fronting].ip is parsed but never used to derive
	// the dial target — the user must migrate to [domain-fronting].host.
	suite.NotNil(conf.DomainFronting.IP.Get(nil))
	suite.Equal("", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("", conf.GetDomainFrontingHost())
}

const webTestBase = `
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[web]
enabled = true
bind-to = "127.0.0.1:8443"
`

func (suite *ConfigTestSuite) TestConfigWebMinimal() {
	conf, err := config.Parse(suite.ReadConfig("web_minimal.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.True(conf.Web.Enabled.Get(false))
	suite.Equal("web.example.com", conf.Web.Hostname.Get(""))
	suite.Equal("http://127.0.0.1:8080", conf.Web.PublicUpstream.String())
	suite.Equal(web.DefaultLimits(), conf.GetWebLimits())
	suite.Equal(web.DefaultTimeouts(), conf.GetWebTimeouts())
	suite.Nil(conf.GetWebTrustedProxies())
}

func (suite *ConfigTestSuite) TestConfigWebOverrides() {
	conf, err := config.Parse(suite.ReadConfig("web_limits.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())

	limits := conf.GetWebLimits()
	defaults := web.DefaultLimits()
	suite.Equal(10, limits.MaxSessions)
	suite.Equal(1<<20, limits.CarrierBatchBytes)
	suite.Equal(300000, limits.MaxPendingItemsGlobal)
	suite.Equal(100000, limits.NewStreamsPerMinute) // above the old 65535 cap
	suite.Equal(defaults.MaxStreams, limits.MaxStreams)

	timeouts := conf.GetWebTimeouts()
	suite.Equal(10*time.Second, timeouts.LongPoll)
	suite.Equal(web.DefaultTimeouts().Shutdown, timeouts.Shutdown)

	suite.Equal([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}, conf.GetWebTrustedProxies())
}

func (suite *ConfigTestSuite) TestConfigWebInvalid() {
	const (
		stageParse    = "parse"
		stageValidate = "validate"
	)

	dir := suite.T().TempDir()

	testData := []struct {
		name  string
		stage string
		extra string
	}{
		{"both public options", stageValidate, `
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
public-dir = "` + dir + `"`},
		{"no public option", stageValidate, `
hostname = "web.example.com"`},
		{"uppercase hostname", stageValidate, `
hostname = "Web.Example.com"
public-upstream = "http://127.0.0.1:8080"`},
		{"no hostname", stageValidate, `
public-upstream = "http://127.0.0.1:8080"`},
		{"https upstream", stageParse, `
hostname = "web.example.com"
public-upstream = "https://127.0.0.1:8080"`},
		{"short token key", stageParse, `
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
token-key = "` + base64.StdEncoding.EncodeToString(make([]byte, 16)) + `"`},
		{"small carrier batch", stageValidate, `
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
[web.limits]
carrier-batch-bytes = "100kib"`},
		{"long poll above default reconnect grace", stageValidate, `
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
[web.timeouts]
long-poll = "3m"`},
	}

	for _, tc := range testData {
		suite.T().Run(tc.name, func(t *testing.T) {
			conf, err := config.Parse([]byte(webTestBase + tc.extra))

			if tc.stage == stageParse {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Error(t, conf.Validate())
		})
	}
}

func (suite *ConfigTestSuite) TestConfigWebNoBindTo() {
	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[web]
enabled = true
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
`))
	suite.NoError(err)
	suite.Error(conf.Validate())
}

func (suite *ConfigTestSuite) TestConfigWebDisabledSkipsValidation() {
	// TypeHost accepts the uppercase name, web.ValidateHostname does not.
	const base = `
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[web]
hostname = "Web.Example.com"
public-upstream = "http://127.0.0.1:8080"
`

	conf, err := config.Parse([]byte(base))
	suite.Require().NoError(err)
	suite.NoError(conf.Validate())

	conf, err = config.Parse([]byte(base + "enabled = true\n"))
	suite.Require().NoError(err)
	suite.Error(conf.Validate())
}

func (suite *ConfigTestSuite) TestConfigWebTokenKeyNotLogged() {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	conf, err := config.Parse([]byte(webTestBase + `
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
token-key = "` + key + `"`))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Len(conf.Web.TokenKey.Get(nil), 32)
	suite.NotContains(conf.String(), key)
}

func TestConfig(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ConfigTestSuite{})
}
