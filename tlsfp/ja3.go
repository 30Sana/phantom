package tlsfp

import (
	"crypto/md5"
	"fmt"
	"strings"

	"phantom/fingerprints"
)

// Compute returns the JA3 raw string and its MD5 hash for the given profile.
// GREASE values are stripped before hashing, per the JA3 spec.
func Compute(p *fingerprints.Profile) (raw, hash string) {
	extIDs := make([]uint16, 0, len(p.Extensions))
	for _, e := range p.Extensions {
		if !isGREASE(e.ID) {
			extIDs = append(extIDs, e.ID)
		}
	}

	raw = fmt.Sprintf("%d,%s,%s,%s,%s",
		p.RecordVersion,
		joinU16(filterGREASE(p.CipherSuites), "-"),
		joinU16(extIDs, "-"),
		joinU16(filterGREASE(p.SupportedGroups), "-"),
		joinU8(p.ECPointFormats, "-"),
	)

	sum := md5.Sum([]byte(raw))
	hash = fmt.Sprintf("%x", sum)
	return raw, hash
}

// isGREASE returns true if v matches the GREASE pattern (RFC 8701):
// both bytes are equal and the low nibble of each is 0xA.
func isGREASE(v uint16) bool {
	lo := byte(v)
	hi := byte(v >> 8)
	return lo == hi && lo&0x0F == 0x0A
}

func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinU16(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinU8(vals []uint8, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}
