package config

import (
	"fmt"
	"strconv"
)

// TypeCount is a positive integer without an upper bound (other than uint).
type TypeCount struct {
	Value uint
}

func (t *TypeCount) Set(value string) error {
	countValue, err := strconv.ParseUint(value, 10, strconv.IntSize)
	if err != nil {
		return fmt.Errorf("value is not uint (%s): %w", value, err)
	}

	if countValue == 0 {
		return fmt.Errorf("value should be >0 (%s)", value)
	}

	t.Value = uint(countValue)

	return nil
}

func (t TypeCount) Get(defaultValue uint) uint {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeCount) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeCount) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeCount) String() string {
	return strconv.FormatUint(uint64(t.Value), 10)
}
