package config_test

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type typeHTTPURLTestStruct struct {
	Value config.TypeHTTPURL `json:"value"`
}

type HTTPURLTestSuite struct {
	suite.Suite
}

func (suite *HTTPURLTestSuite) TestUnmarshalFail() {
	testData := []string{
		"",
		"http://",
		"://lala",
		"/path",
		"https://127.0.0.1:8080",
		"socks5://127.0.0.1",
		"http://example.com",
		"http://localhost:8080",
		"http://8.8.8.8",
		"http://[2001:db8::1]:80",
		"http://user:pass@127.0.0.1",
		"http://127.0.0.1/path",
		"http://127.0.0.1/?q=1",
		"http://127.0.0.1/#frag",
		"http://127.0.0.1:99999",
	}

	for _, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal(data, &typeHTTPURLTestStruct{}))
		})
	}
}

func (suite *HTTPURLTestSuite) TestUnmarshalOk() {
	testData := map[string]string{
		"http://127.0.0.1":       "http://127.0.0.1",
		"http://127.0.0.1/":      "http://127.0.0.1",
		"http://127.0.0.1:8080":  "http://127.0.0.1:8080",
		"http://127.0.0.1:8080/": "http://127.0.0.1:8080",
		"http://10.1.2.3:80":     "http://10.1.2.3:80",
		"http://192.168.0.5":     "http://192.168.0.5",
		"http://172.16.0.1":      "http://172.16.0.1",
		"http://169.254.1.1":     "http://169.254.1.1",
		"http://[::1]":           "http://[::1]",
		"http://[::1]:9000":      "http://[::1]:9000",
		"http://[fd00::1]:9000":  "http://[fd00::1]:9000",
		"http://[fe80::1]:9000":  "http://[fe80::1]:9000",
		"http://[fe80::1]:9000/": "http://[fe80::1]:9000",
	}

	for k, v := range testData {
		want := v

		data, err := json.Marshal(map[string]string{
			"value": k,
		})
		suite.NoError(err)

		suite.T().Run(k, func(t *testing.T) {
			testStruct := &typeHTTPURLTestStruct{}
			assert.NoError(t, json.Unmarshal(data, testStruct))
			assert.Equal(t, want, testStruct.Value.String())
			assert.Equal(t, "http", testStruct.Value.Get(nil).Scheme)
			assert.Empty(t, testStruct.Value.Get(nil).Path)
		})
	}
}

func (suite *HTTPURLTestSuite) TestMarshalOk() {
	parsed, _ := url.Parse("http://127.0.0.1:8080")
	testStruct := &typeHTTPURLTestStruct{
		Value: config.TypeHTTPURL{
			Value: parsed,
		},
	}

	encodedJSON, err := json.Marshal(testStruct)
	suite.NoError(err)
	suite.JSONEq(`{"value": "http://127.0.0.1:8080"}`,
		string(encodedJSON))
}

func (suite *HTTPURLTestSuite) TestGet() {
	emptyURL := &url.URL{}

	value := config.TypeHTTPURL{}
	suite.Equal(emptyURL, value.Get(emptyURL))

	value.Value = &url.URL{}
	suite.Equal(value.Value, value.Get(emptyURL))
}

func TestTypeHTTPURL(t *testing.T) {
	t.Parallel()
	suite.Run(t, &HTTPURLTestSuite{})
}
