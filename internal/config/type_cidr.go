package config

import (
	"fmt"
	"net/netip"
)

// TypeCIDR is an IP network. A bare IP address is accepted as a single-host
// network.
type TypeCIDR struct {
	Value netip.Prefix
}

func (t *TypeCIDR) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return fmt.Errorf("incorrect CIDR (%s): %w", value, err)
		}

		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	t.Value = prefix.Masked()

	return nil
}

func (t TypeCIDR) Get(defaultValue netip.Prefix) netip.Prefix {
	if !t.Value.IsValid() {
		return defaultValue
	}

	return t.Value
}

func (t *TypeCIDR) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeCIDR) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeCIDR) String() string {
	if !t.Value.IsValid() {
		return ""
	}

	return t.Value.String()
}
