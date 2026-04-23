package fingerprints

// Profile holds every field needed to reconstruct a TLS ClientHello that matches
// a known browser or device. The extension list is ordered — the order matters
// for fingerprinting, so don't shuffle it.
type Profile struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`

	// RecordVersion is the version sent in the ClientHello version field.
	// Modern browsers send 771 (TLS 1.2) here even when they support TLS 1.3 —
	// actual version negotiation happens via the supported_versions extension.
	RecordVersion uint16 `json:"record_version"`

	CipherSuites       []uint16  `json:"cipher_suites"`
	CompressionMethods []uint8   `json:"compression_methods"`
	Extensions         []ExtSpec `json:"extensions"`

	// These are referenced by their respective extension builders.
	SupportedGroups        []uint16 `json:"supported_groups"`
	ECPointFormats         []uint8  `json:"ec_point_formats"`
	SupportedVersions      []uint16 `json:"supported_versions"`
	SignatureAlgorithms    []uint16 `json:"signature_algorithms"`
	ALPN                   []string `json:"alpn"`
	ALPSProtocols          []string `json:"alps_protocols"` // extension 17513 — usually just ["h2"]
	PSKKeyExchangeModes    []uint8  `json:"psk_key_exchange_modes"`
	CompressCertAlgorithms []uint16 `json:"compress_cert_algorithms"`

	// KeyShareGroups controls which groups get key shares in the key_share extension.
	// GREASE key shares require a 1-byte dummy payload — the rewriter handles this automatically.
	KeyShareGroups []uint16 `json:"key_share_groups"`
}

// ExtSpec is a single TLS extension identified by its numeric type ID.
// 0x0a0a (2570) is the GREASE placeholder — it appears in cipher suites,
// extension lists, and supported groups wherever GREASE values go.
type ExtSpec struct {
	ID uint16 `json:"id"`
}
