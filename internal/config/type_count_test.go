package config_test

import (
	"encoding/json"
	"testing"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type typeCountTestStruct struct {
	Value config.TypeCount `json:"value"`
}

type CountTestSuite struct {
	suite.Suite
}

func (suite *CountTestSuite) TestUnmarshalFail() {
	testData := []string{
		`"1"`,
		`"x"`,
		`0`,
		`-1`,
		`1.5`,
		`99999999999999999999999`,
		`null`,
	}

	for _, v := range testData {
		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal([]byte(`{"value": `+v+`}`), &typeCountTestStruct{}))
		})
	}
}

func (suite *CountTestSuite) TestUnmarshalOk() {
	testData := map[string]uint{
		"1":      1,
		"65535":  65535,
		"65536":  65536,
		"300000": 300000,
	}

	for k, v := range testData {
		want := v

		suite.T().Run(k, func(t *testing.T) {
			testStruct := &typeCountTestStruct{}
			assert.NoError(t, json.Unmarshal([]byte(`{"value": `+k+`}`), testStruct))
			assert.Equal(t, want, testStruct.Value.Get(0))
		})
	}
}

func (suite *CountTestSuite) TestMarshalOk() {
	encodedJSON, err := json.Marshal(&typeCountTestStruct{Value: config.TypeCount{Value: 300000}})
	suite.NoError(err)
	suite.JSONEq(`{"value": 300000}`, string(encodedJSON))
}

func (suite *CountTestSuite) TestGet() {
	value := config.TypeCount{}
	suite.Equal(uint(7), value.Get(7))

	value.Value = 300000
	suite.Equal(uint(300000), value.Get(7))
}

func TestTypeCount(t *testing.T) {
	t.Parallel()
	suite.Run(t, &CountTestSuite{})
}
