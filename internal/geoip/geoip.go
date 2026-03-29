package geoip

import (
	"fmt"
	"net"
)

// Location holds the resolved geographic context for an IP address.
type Location struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	City        string `json:"city,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	IsPrivate   bool   `json:"is_private"`
}

// DB wraps a MaxMind GeoLite2 database reader.
// Using an interface here so we can swap in a stub when no .mmdb is present.
type DB struct {
	path   string
	loaded bool
	// reader will hold *geoip2.Reader once the MaxMind dependency is added.
	// For now the field is unexported and the package compiles without it.
}

// Open loads a GeoLite2-City.mmdb from the given path.
// Returns a no-op DB (IsPrivate detection only) if path is empty or file missing.
func Open(path string) (*DB, error) {
	if path == "" {
		return &DB{}, nil
	}
	// TODO(P3): import github.com/oschwald/geoip2-golang and open the .mmdb here.
	// For now we return a DB that can at least classify private IP ranges.
	return &DB{path: path, loaded: false}, nil
}

// Lookup resolves a raw IP string to a Location.
// Falls back to private-range detection when the .mmdb is not loaded.
func (db *DB) Lookup(rawIP string) Location {
	ip := net.ParseIP(rawIP)
	loc := Location{IP: rawIP}

	if ip == nil {
		return loc
	}

	loc.IsPrivate = isPrivate(ip)

	if !db.loaded {
		// Without the mmdb, we can only report private/public.
		if loc.IsPrivate {
			loc.CountryName = "Private Network"
		}
		return loc
	}

	// TODO(P3): call the geoip2 reader here and populate CountryCode, City, ASN.
	return loc
}

// Close releases the underlying database reader.
func (db *DB) Close() error {
	if !db.loaded {
		return nil
	}
	// TODO(P3): reader.Close()
	return nil
}

// private IP ranges per RFC 1918, RFC 4193, RFC 5735
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"169.254.0.0/16", // link-local
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("geoip: bad CIDR %s: %v", c, err))
		}
		privateRanges = append(privateRanges, ipnet)
	}
}

func isPrivate(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
