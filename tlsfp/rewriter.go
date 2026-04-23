package tlsfp

import (
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"phantom/fingerprints"
)

// greaseVal is the GREASE placeholder used in JSON profiles (0x0a0a).
// utls randomizes the actual GREASE value per connection; we just mark the slots.
const greaseVal = 0x0a0a

// Dial sets up a utls connection over conn using the given fingerprint profile.
// The caller must call Handshake() on the returned UConn before reading/writing.
func Dial(conn net.Conn, serverName string, p *fingerprints.Profile) (*utls.UConn, error) {
	cfg := &utls.Config{
		ServerName: serverName,
	}

	spec, err := buildSpec(p)
	if err != nil {
		return nil, err
	}

	uc := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("applying ClientHello preset: %w", err)
	}

	return uc, nil
}

func buildSpec(p *fingerprints.Profile) (*utls.ClientHelloSpec, error) {
	exts, err := buildExtensions(p)
	if err != nil {
		return nil, err
	}

	ciphers := make([]uint16, 0, len(p.CipherSuites))
	for _, c := range p.CipherSuites {
		if c == greaseVal {
			ciphers = append(ciphers, utls.GREASE_PLACEHOLDER)
		} else {
			ciphers = append(ciphers, c)
		}
	}

	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS10,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       ciphers,
		CompressionMethods: p.CompressionMethods,
		Extensions:         exts,
		GetSessionID:       nil,
	}, nil
}

func buildExtensions(p *fingerprints.Profile) ([]utls.TLSExtension, error) {
	out := make([]utls.TLSExtension, 0, len(p.Extensions))
	for _, e := range p.Extensions {
		ext, err := makeExt(e.ID, p)
		if err != nil {
			return nil, fmt.Errorf("extension 0x%04x: %w", e.ID, err)
		}
		out = append(out, ext)
	}
	return out, nil
}

func makeExt(id uint16, p *fingerprints.Profile) (utls.TLSExtension, error) {
	switch id {
	case greaseVal:
		return &utls.UtlsGREASEExtension{}, nil

	case 0: // server_name
		return &utls.SNIExtension{}, nil

	case 5: // status_request (OCSP)
		return &utls.StatusRequestExtension{}, nil

	case 10: // supported_groups
		groups := make([]utls.CurveID, 0, len(p.SupportedGroups))
		for _, g := range p.SupportedGroups {
			if g == greaseVal {
				groups = append(groups, utls.GREASE_PLACEHOLDER)
			} else {
				groups = append(groups, utls.CurveID(g))
			}
		}
		return &utls.SupportedCurvesExtension{Curves: groups}, nil

	case 11: // ec_point_formats
		return &utls.SupportedPointsExtension{SupportedPoints: p.ECPointFormats}, nil

	case 13: // signature_algorithms
		algs := make([]utls.SignatureScheme, len(p.SignatureAlgorithms))
		for i, a := range p.SignatureAlgorithms {
			algs[i] = utls.SignatureScheme(a)
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algs}, nil

	case 16: // application_layer_protocol_negotiation
		return &utls.ALPNExtension{AlpnProtocols: p.ALPN}, nil

	case 17: // status_request_v2 — Safari uses this
		return &utls.GenericExtension{Id: 17}, nil

	case 18: // signed_certificate_timestamp
		return &utls.SCTExtension{}, nil

	case 21: // padding
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil

	case 22: // encrypt_then_mac
		return &utls.GenericExtension{Id: 22}, nil

	case 23: // extended_master_secret
		return &utls.ExtendedMasterSecretExtension{}, nil

	case 27: // compress_certificate
		algos := make([]utls.CertCompressionAlgo, 0, len(p.CompressCertAlgorithms))
		for _, a := range p.CompressCertAlgorithms {
			algos = append(algos, utls.CertCompressionAlgo(a))
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algos}, nil

	case 28: // record_size_limit
		return &utls.FakeRecordSizeLimitExtension{Limit: 0x4001}, nil

	case 34: // delegated_credentials
		return &utls.GenericExtension{Id: 34}, nil

	case 35: // session_ticket
		return &utls.SessionTicketExtension{}, nil

	case 43: // supported_versions
		vers := make([]uint16, 0, len(p.SupportedVersions))
		for _, v := range p.SupportedVersions {
			if v == greaseVal {
				vers = append(vers, utls.GREASE_PLACEHOLDER)
			} else {
				vers = append(vers, v)
			}
		}
		return &utls.SupportedVersionsExtension{Versions: vers}, nil

	case 45: // psk_key_exchange_modes
		return &utls.PSKKeyExchangeModesExtension{Modes: p.PSKKeyExchangeModes}, nil

	case 51: // key_share
		ks := make([]utls.KeyShare, 0, len(p.KeyShareGroups))
		for _, g := range p.KeyShareGroups {
			if g == greaseVal {
				// GREASE key shares must carry a 1-byte dummy payload.
				// Without it utls sends a zero-length key_exchange which is
				// a protocol violation and causes servers to reject the ClientHello.
				ks = append(ks, utls.KeyShare{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}})
			} else {
				ks = append(ks, utls.KeyShare{Group: utls.CurveID(g)})
			}
		}
		return &utls.KeyShareExtension{KeyShares: ks}, nil

	case 17513: // application_settings (ALPS) — Chrome-specific, h2 only
		return &utls.ApplicationSettingsExtension{SupportedProtocols: p.ALPSProtocols}, nil

	case 65281: // renegotiation_info
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil

	default:
		return &utls.GenericExtension{Id: id}, nil
	}
}
