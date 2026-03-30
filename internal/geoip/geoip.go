package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
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
type DB struct {
	reader *geoip2.Reader
	loaded bool
}

// Open loads a GeoLite2-City.mmdb from the given path.
// Returns a no-op DB (IsPrivate detection only) if path is empty.
// Returns an error only if the path is non-empty but the file can't be opened.
func Open(path string) (*DB, error) {
	if path == "" {
		return &DB{}, nil
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: failed to open %s: %w", path, err)
	}
	return &DB{reader: r, loaded: true}, nil
}

// Lookup resolves a raw IP string to a Location.
// Falls back to private-range detection only when the .mmdb is not loaded.
func (db *DB) Lookup(rawIP string) Location {
	ip := net.ParseIP(rawIP)
	loc := Location{IP: rawIP}

	if ip == nil {
		return loc
	}

	loc.IsPrivate = isPrivate(ip)

	if !db.loaded || db.reader == nil {
		if loc.IsPrivate {
			loc.CountryName = "Private Network"
		}
		return loc
	}

	// City record gives us country + city in one query.
	record, err := db.reader.City(ip)
	if err == nil {
		loc.CountryCode = record.Country.IsoCode
		if name, ok := record.Country.Names["en"]; ok {
			loc.CountryName = name
		}
		if name, ok := record.City.Names["en"]; ok {
			loc.City = name
		}
	}

	return loc
}

// Close releases the underlying database reader.
func (db *DB) Close() error {
	if db.reader != nil {
		return db.reader.Close()
	}
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
