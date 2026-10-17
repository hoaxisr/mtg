package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type typeDirectoryTestStruct struct {
	Value config.TypeDirectory `json:"value"`
}

type DirectoryTestSuite struct {
	suite.Suite
}

func (suite *DirectoryTestSuite) TestUnmarshalFail() {
	dir := suite.T().TempDir()
	file := filepath.Join(dir, "file.txt")
	suite.NoError(os.WriteFile(file, []byte("x"), 0o600))

	testData := []string{
		"",
		filepath.Join(dir, "missing"),
		file,
	}

	for _, v := range testData {
		data, err := json.Marshal(map[string]string{
			"value": v,
		})
		suite.NoError(err)

		suite.T().Run(v, func(t *testing.T) {
			assert.Error(t, json.Unmarshal(data, &typeDirectoryTestStruct{}))
		})
	}
}

func (suite *DirectoryTestSuite) TestUnmarshalOk() {
	dir := suite.T().TempDir()

	testData := map[string]string{
		dir:                     dir,
		dir + "/":               dir,
		filepath.Join(dir, "."): dir,
	}

	for k, v := range testData {
		want := v

		data, err := json.Marshal(map[string]string{
			"value": k,
		})
		suite.NoError(err)

		suite.T().Run(k, func(t *testing.T) {
			testStruct := &typeDirectoryTestStruct{}
			assert.NoError(t, json.Unmarshal(data, testStruct))
			assert.Equal(t, want, testStruct.Value.Get(""))
			assert.Equal(t, want, testStruct.Value.String())
		})
	}
}

func (suite *DirectoryTestSuite) TestMarshalOk() {
	testStruct := &typeDirectoryTestStruct{
		Value: config.TypeDirectory{Value: "/some/dir"},
	}

	encodedJSON, err := json.Marshal(testStruct)
	suite.NoError(err)
	suite.JSONEq(`{"value": "/some/dir"}`, string(encodedJSON))
}

func (suite *DirectoryTestSuite) TestGet() {
	value := config.TypeDirectory{}
	suite.Equal("def", value.Get("def"))

	value.Value = "/x"
	suite.Equal("/x", value.Get("def"))
}

func TestTypeDirectory(t *testing.T) {
	t.Parallel()
	suite.Run(t, &DirectoryTestSuite{})
}
