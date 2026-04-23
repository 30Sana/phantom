<div align="center">

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

**TLS fingerprint impersonation proxy for anti-bot research**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)
[![Built with utls](https://img.shields.io/badge/built%20with-utls-5C2D91?style=flat)](https://github.com/refraction-networking/utls)

</div>

---

Phantom is a local MITM proxy that intercepts outbound HTTPS traffic and rewrites the TLS `ClientHello` in real-time to impersonate a specific browser or device. Anti-bot systems like Cloudflare, Akamai, and DataDome fingerprint TLS handshakes via [JA3](https://github.com/salesforce/ja3) hashes to tell bots from browsers — Phantom lets you study exactly how they respond to different fingerprints.

## How it works

```
Browser / curl / script
        │
        │  HTTP CONNECT (or plain HTTP)
        ▼
┌───────────────────────┐
│     Phantom :8080     │
│                       │
│  ┌─────────────────┐  │
│  │  MITM CA cert   │  │  ◄── your browser trusts this
│  └────────┬────────┘  │
│           │ signs leaf cert per host
│  ┌────────▼────────┐  │
│  │  utls rewriter  │  │  ◄── rewrites ClientHello to match a profile
│  └────────┬────────┘  │
└───────────┼───────────┘
            │  spoofed TLS handshake (JA3 = target profile)
            ▼
     api.example.com:443
```

1. Your browser connects to Phantom and sends a `CONNECT` for HTTPS sites
2. Phantom does TLS termination using a CA-signed leaf cert (MITM)
3. Phantom dials the real target using **[utls](https://github.com/refraction-networking/utls)** with a custom `ClientHelloSpec` matching the loaded profile
4. The JA3 hash of every outbound handshake is printed (or shown in the dashboard)
5. Traffic is bridged between both TLS sessions

---

## Installation

**Requirements:** Go 1.22+

```bash
git clone https://github.com/yourname/phantom
cd phantom
go build -o phantom ./cmd/phantom

# Optionally install to PATH
go install ./cmd/phantom
```

---

## Quick Start

**Step 1 — Run the proxy**

```bash
./phantom
# CA cert: /Users/you/.phantom/ca.crt
# Add it to your OS trust store to avoid certificate warnings.
# phantom listening on 127.0.0.1:8080  profile="Chrome 120"
```

**Step 2 — Trust the CA cert** (one-time)

<details>
<summary>macOS</summary>

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.phantom/ca.crt
```
</details>

<details>
<summary>Linux (Ubuntu / Debian)</summary>

```bash
sudo cp ~/.phantom/ca.crt /usr/local/share/ca-certificates/phantom.crt
sudo update-ca-certificates
```
</details>

<details>
<summary>Firefox (any OS)</summary>

Go to `about:preferences#privacy` → scroll to **Certificates** → **View Certificates** → **Authorities** tab → **Import** → select `~/.phantom/ca.crt` → check "Trust this CA to identify websites".
</details>

<details>
<summary>Windows</summary>

```powershell
certutil -addstore -f "ROOT" $env:USERPROFILE\.phantom\ca.crt
```
</details>

**Step 3 — Configure your browser**

Set your browser or system proxy to **HTTP proxy: `127.0.0.1:8080`**.

In Firefox: Preferences → Network Settings → Manual proxy → HTTP Proxy `127.0.0.1`, Port `8080`, check "Also use this proxy for HTTPS".

**Step 4 — Verify the fingerprint**

Visit [https://tls.peet.ws/api/all](https://tls.peet.ws/api/all) in your browser. The `ja3` field in the JSON response should match the profile you loaded.

```bash
# Quick curl check
curl -x http://127.0.0.1:8080 https://tls.peet.ws/api/all | python3 -m json.tool | grep ja3
```

---

## Usage

```
Usage:
  phantom [flags]
  phantom [command]

Flags:
  -a, --addr string           listen address (default "127.0.0.1:8080")
  -d, --dashboard             show live connection dashboard (TUI)
  -p, --profile string        built-in profile to use (default "chrome_120")
  -f, --profile-file string   load profile from a JSON file instead of a built-in
  -v, --verbose               log extra detail per connection
  -h, --help                  help for phantom

Commands:
  profiles    List available built-in fingerprint profiles
```

### Examples

```bash
# Default — Chrome 120 fingerprint, port 8080
./phantom

# Use a different built-in profile
./phantom -p firefox_121

# Load a custom profile from disk
./phantom -f ./my_profile.json

# Show the live connection dashboard
./phantom -d

# Different port, verbose logging
./phantom -a 127.0.0.1:9090 -v

# List all built-in profiles
./phantom profiles
```

### Live Dashboard

```bash
./phantom --dashboard
```

```
  PHANTOM  TLS fingerprint impersonation proxy

  profile: Chrome 120    addr: 127.0.0.1:8080    total: 14

  TIME        HOST                              JA3
  ──────────────────────────────────────────────────────────────────────────
  14:22:01    tls.peet.ws                       cd08e31d4a6b3c14e9df9c6a...
  14:21:58    api.github.com                    cd08e31d4a6b3c14e9df9c6a...
  14:21:44    fonts.googleapis.com              cd08e31d4a6b3c14e9df9c6a...

  press q to quit
```

---

## Built-in Profiles

| ID | Name | Notes |
|----|------|-------|
| `chrome_120` | Chrome 120 | GREASE enabled, brotli compress-cert, ALPS |
| `firefox_121` | Firefox 121 | No GREASE, record size limit extension |
| `safari_17` | Safari 17 | Apple Security framework stack, status_request_v2 |
| `curl_8` | curl 8 | OpenSSL-linked curl, simple and easy to detect |

```bash
./phantom profiles
```

---

## Custom Profiles

Profiles are plain JSON files. Load one with `-f`:

```bash
./phantom -f my_mobile_app.json
```

**Profile format:**

```jsonc
{
  "name": "My App v2",
  "id": "my_app_v2",
  "description": "iOS 17 URLSession fingerprint",

  // Version sent in the ClientHello version field.
  // Modern clients send 771 (TLS 1.2) even when supporting TLS 1.3.
  "record_version": 771,

  // 2570 (0x0a0a) is the GREASE placeholder — Phantom randomizes it per connection.
  "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392],

  "compression_methods": [0],

  // Extensions in exact wire order — order matters for the JA3 hash.
  "extensions": [
    {"id": 2570},   // GREASE
    {"id": 0},      // SNI
    {"id": 23},     // extended_master_secret
    {"id": 65281},  // renegotiation_info
    {"id": 10},     // supported_groups
    {"id": 11},     // ec_point_formats
    {"id": 35},     // session_ticket
    {"id": 16},     // ALPN
    {"id": 5},      // status_request
    {"id": 13},     // signature_algorithms
    {"id": 51},     // key_share
    {"id": 45},     // psk_key_exchange_modes
    {"id": 43},     // supported_versions
    {"id": 21}      // padding
  ],

  "supported_groups":        [2570, 29, 23, 24],
  "ec_point_formats":        [0],
  "signature_algorithms":    [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
  "alpn":                    ["h2", "http/1.1"],
  "supported_versions":      [2570, 772, 771],
  "psk_key_exchange_modes":  [1],
  "compress_cert_algorithms": [],
  "key_share_groups":        [2570, 29]
}
```

**Common extension IDs for reference:**

| ID | Name |
|----|------|
| 0 | server_name (SNI) |
| 5 | status_request (OCSP) |
| 10 | supported_groups |
| 11 | ec_point_formats |
| 13 | signature_algorithms |
| 16 | ALPN |
| 18 | signed_certificate_timestamp |
| 21 | padding |
| 23 | extended_master_secret |
| 27 | compress_certificate |
| 28 | record_size_limit |
| 35 | session_ticket |
| 43 | supported_versions |
| 45 | psk_key_exchange_modes |
| 51 | key_share |
| 17513 | application_settings (ALPS) |
| 65281 | renegotiation_info |
| 2570 | GREASE placeholder |

---

## Understanding JA3

JA3 is an MD5 hash of five fields extracted from the TLS `ClientHello`:

```
JA3 = md5(Version,Ciphers,Extensions,Curves,PointFormats)
```

GREASE values (`0x?A?A`) are stripped before hashing. Two clients with identical values across these fields produce the same JA3 hash, which is what anti-bot systems use for detection.

Phantom computes and logs the JA3 hash for each connection so you can verify the spoof matches the expected value for your chosen profile.

**Useful resources:**
- [JA3 database](https://ja3er.com) — look up known hashes
- [tls.peet.ws](https://tls.peet.ws) — inspect your live TLS fingerprint
- [howsitmgoing.com](https://howsitmgoing.com) — anti-bot detection test page

---

## Project Layout

```
phantom/
├── cmd/phantom/        CLI entrypoint (cobra)
├── proxy/
│   ├── proxy.go        HTTP proxy server, CONNECT handler, HTTP forwarding
│   ├── mitm.go         CA cert generation, per-host leaf cert signing
│   └── bridge.go       Bidirectional TCP bridge
├── tlsfp/
│   ├── rewriter.go     utls ClientHelloSpec builder from profile
│   └── ja3.go          JA3 hash computation
├── fingerprints/
│   ├── profile.go      Profile struct
│   ├── loader.go       JSON loading from disk
│   ├── registry.go     Embedded profile registry
│   └── builtin/        Built-in JSON fingerprint profiles
└── tui/
    └── tui.go          Bubbletea live dashboard
```

---

## Limitations & Notes

- **HTTP sites** are forwarded transparently — TLS fingerprinting only applies to HTTPS
- **Certificate pinning** will break MITM for apps that pin their server cert (most mobile apps)
- **TLS 1.3 0-RTT** is not supported
- The CA cert is valid for 10 years; rotate it by deleting `~/.phantom/ca.crt` and `~/.phantom/ca.key`
- Profiles are research-quality approximations; minor differences from real browser behaviour are expected

---

## License

MIT
