package config_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type typeCIDRTestStruct struct {
	Value config.TypeCIDR `json:"value"`
}

type CIDRTestSuite struct {
	suite.Suite
}

func (suite *CIDRTestSuite) TestUnmarshalFail() {
	testData := []string{
		"",
		"lala",
		"10.0.0.0/33",
		"10.0.0.0/-1",
		"::1/129",
		"10.0.0.256/8",
		"example.com",
	}

	for _, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal(data, &typeCIDRTestStruct{}))
		})
	}
}

func (suite *CIDRTestSuite) TestUnmarshalOk() {
	testData := map[string]string{
		"10.0.0.0/8":      "10.0.0.0/8",
		"10.1.2.3/8":      "10.0.0.0/8",
		"127.0.0.1":       "127.0.0.1/32",
		"::1":             "::1/128",
		"::ffff:10.0.0.1": "10.0.0.1/32",
		"fd00::/8":        "fd00::/8",
		"192.168.1.7/24":  "192.168.1.0/24",
	}

	for k, v := range testData {
		want := v

		data, err := json.Marshal(map[string]string{
			"value": k,
		})
		suite.NoError(err)

		suite.T().Run(k, func(t *testing.T) {
			testStruct := &typeCIDRTestStruct{}
			assert.NoError(t, json.Unmarshal(data, testStruct))
			assert.Equal(t, want, testStruct.Value.String())
			assert.Equal(t, netip.MustParsePrefix(want), testStruct.Value.Get(netip.Prefix{}))
		})
	}
}

func (suite *CIDRTestSuite) TestMarshalOk() {
	testStruct := &typeCIDRTestStruct{
		Value: config.TypeCIDR{Value: netip.MustParsePrefix("10.0.0.0/8")},
	}

	encodedJSON, err := json.Marshal(testStruct)
	suite.NoError(err)
	suite.JSONEq(`{"value": "10.0.0.0/8"}`, string(encodedJSON))
}

func (suite *CIDRTestSuite) TestGet() {
	def := netip.MustParsePrefix("1.2.3.4/32")

	value := config.TypeCIDR{}
	suite.Equal(def, value.Get(def))
	suite.Equal("", value.String())

	value.Value = netip.MustParsePrefix("10.0.0.0/8")
	suite.Equal(value.Value, value.Get(def))
}

func TestTypeCIDR(t *testing.T) {
	t.Parallel()
	suite.Run(t, &CIDRTestSuite{})
}
