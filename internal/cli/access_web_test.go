package cli

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/9seconds/mtg/v2/internal/testlib"
	"github.com/9seconds/mtg/v2/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestAccessIncludesWeb(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[web]
enabled = true
bind-to = "127.0.0.1:8443"
hostname = "web.example.com"
public-upstream = "http://127.0.0.1:8080"
`), 0o600))

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	var runErr error

	out := testlib.CaptureStdout(func() {
		runErr = (&Access{
			ConfigPath: path,
			PublicIPv4: net.ParseIP("1.2.3.4"),
			PublicIPv6: net.ParseIP("2001:db8::1"),
		}).Run(&CLI{}, "test")
	})
	require.NoError(t, runErr)

	var resp struct {
		Web *struct {
			Hostname  string `json:"hostname"`
			Secret    string `json:"secret"`
			TgURL     string `json:"tg_url"`     //nolint: tagliatelle
			TgQrCode  string `json:"tg_qrcode"`  //nolint: tagliatelle
			TmeURL    string `json:"tme_url"`    //nolint: tagliatelle
			TmeQrCode string `json:"tme_qrcode"` //nolint: tagliatelle
		} `json:"web"`
	}

	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.NotNil(t, resp.Web)
	require.Equal(t, "web.example.com", resp.Web.Hostname)
	require.Equal(t, "dd"+hex.EncodeToString(conf.Secret.Key[:]), resp.Web.Secret)
	require.True(t, strings.HasPrefix(resp.Web.TgURL, "tg://webproxy?server="), resp.Web.TgURL)
	require.True(t, strings.HasPrefix(resp.Web.TmeURL, "https://t.me/webproxy?server="), resp.Web.TmeURL)
	require.NotEmpty(t, resp.Web.TgQrCode)
	require.NotEmpty(t, resp.Web.TmeQrCode)
}
