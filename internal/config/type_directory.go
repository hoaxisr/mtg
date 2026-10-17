package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// TypeDirectory is a path to an existing directory.
type TypeDirectory struct {
	Value string
}

func (t *TypeDirectory) Set(value string) error {
	if value == "" {
		return fmt.Errorf("directory cannot be empty")
	}

	info, err := os.Stat(value)
	if err != nil {
		return fmt.Errorf("cannot access directory %q: %w", value, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", value)
	}

	t.Value = filepath.Clean(value)

	return nil
}

func (t TypeDirectory) Get(defaultValue string) string {
	if t.Value == "" {
		return defaultValue
	}

	return t.Value
}

func (t *TypeDirectory) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeDirectory) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeDirectory) String() string {
	return t.Value
}
