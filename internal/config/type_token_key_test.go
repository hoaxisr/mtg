package config_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type typeTokenKeyTestStruct struct {
	Value config.TypeTokenKey `json:"value"`
}

type TokenKeyTestSuite struct {
	suite.Suite
}

func tokenKeyBytes(n int) []byte {
	// 0xfb 0xff produce '+' and '/' in std base64 ('-' and '_' in URL one).
	return bytes.Repeat([]byte{0xfb, 0xff}, n)[:n]
}

func (suite *TokenKeyTestSuite) TestUnmarshalFail() {
	testData := []string{
		"",
		"!!!not-base64!!!",
		base64.StdEncoding.EncodeToString(tokenKeyBytes(16)),
		base64.StdEncoding.EncodeToString(tokenKeyBytes(31)),
		base64.StdEncoding.EncodeToString(tokenKeyBytes(33)),
		base64.RawURLEncoding.EncodeToString(tokenKeyBytes(64)),
	}

	for _, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal(data, &typeTokenKeyTestStruct{}))
		})
	}
}

func (suite *TokenKeyTestSuite) TestUnmarshalOk() {
	key := tokenKeyBytes(32)

	testData := map[string]string{
		"std padded": base64.StdEncoding.EncodeToString(key),
		"std raw":    base64.RawStdEncoding.EncodeToString(key),
		"url padded": base64.URLEncoding.EncodeToString(key),
		"url raw":    base64.RawURLEncoding.EncodeToString(key),
	}

	for name, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(name, func(t *testing.T) {
			testStruct := &typeTokenKeyTestStruct{}
			assert.NoError(t, json.Unmarshal(data, testStruct))
			assert.Equal(t, key, testStruct.Value.Get(nil))
		})
	}
}

func (suite *TokenKeyTestSuite) TestStringIsRedacted() {
	key := tokenKeyBytes(32)
	value := config.TypeTokenKey{}
	suite.Equal("", value.String())

	value.Value = key

	suite.NotContains(value.String(), base64.StdEncoding.EncodeToString(key))
	suite.NotContains(value.String(), base64.RawURLEncoding.EncodeToString(key))

	encodedJSON, err := json.Marshal(&typeTokenKeyTestStruct{Value: value})
	suite.NoError(err)
	suite.NotContains(string(encodedJSON), base64.StdEncoding.EncodeToString(key))
	suite.NotContains(string(encodedJSON), base64.RawURLEncoding.EncodeToString(key))
}

func (suite *TokenKeyTestSuite) TestGet() {
	def := []byte{1}

	value := config.TypeTokenKey{}
	suite.Equal(def, value.Get(def))

	value.Value = tokenKeyBytes(32)
	suite.Equal(value.Value, value.Get(def))
}

func TestTypeTokenKey(t *testing.T) {
	t.Parallel()
	suite.Run(t, &TokenKeyTestSuite{})
}
