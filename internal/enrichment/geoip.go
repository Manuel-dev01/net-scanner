package enrichment

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// GeoResult holds the geographic location data for an IP address.
type GeoResult struct {
	CountryCode string
	CountryName string
	Continent   string
	Latitude    float64
	Longitude   float64
}

// GeoEnricher looks up IP addresses in a MaxMind GeoLite2 database.
type GeoEnricher struct {
	db *maxminddb.Reader
}

// NewGeoEnricher opens the MaxMind .mmdb database at the given path.
func NewGeoEnricher(dbPath string) (*GeoEnricher, error) {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open geoip db: %w", err)
	}
	return &GeoEnricher{db: db}, nil
}

// Lookup returns geographic data for an IP address.
// Returns nil if the IP is not found in the database.
func (g *GeoEnricher) Lookup(ip net.IP) (*GeoResult, error) {
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
			Names   struct {
				En string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"country"`
		Continent struct {
			Code string `maxminddb:"code"`
			Names struct {
				En string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"continent"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}

	err := g.db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("geoip lookup: %w", err)
	}

	if record.Country.ISOCode == "" {
		return nil, nil // not found
	}

	return &GeoResult{
		CountryCode: record.Country.ISOCode,
		CountryName: record.Country.Names.En,
		Continent:   record.Continent.Names.En,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
	}, nil
}

// Close closes the underlying database.
func (g *GeoEnricher) Close() error {
	return g.db.Close()
}
