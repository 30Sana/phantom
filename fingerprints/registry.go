package fingerprints

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed builtin/*.json
var builtinFS embed.FS

var builtinProfiles map[string]*Profile

func init() {
	builtinProfiles = make(map[string]*Profile)

	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		panic("reading embedded profiles: " + err.Error())
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			panic("reading embedded profile " + e.Name() + ": " + err.Error())
		}
		p, err := parseProfile(data)
		if err != nil {
			panic("parsing embedded profile " + e.Name() + ": " + err.Error())
		}
		builtinProfiles[p.ID] = p
	}
}

// Get returns a built-in profile by ID.
func Get(id string) (*Profile, error) {
	p, ok := builtinProfiles[id]
	if !ok {
		return nil, fmt.Errorf("no built-in profile %q — run 'phantom profiles' to see what's available", id)
	}
	return p, nil
}

// List returns all built-in profiles.
func List() []*Profile {
	out := make([]*Profile, 0, len(builtinProfiles))
	for _, p := range builtinProfiles {
		out = append(out, p)
	}
	return out
}
