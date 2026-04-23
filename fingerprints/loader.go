package fingerprints

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFromFile reads and parses a fingerprint profile from a JSON file on disk.
func LoadFromFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}
	return parseProfile(data)
}

func parseProfile(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile JSON: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("profile is missing the 'id' field")
	}
	return &p, nil
}
