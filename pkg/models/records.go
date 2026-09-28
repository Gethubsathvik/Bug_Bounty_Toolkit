package models

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// RecordType enumerates the DNS record types the toolkit collects.
type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
	RecordMX    RecordType = "MX"
	RecordNS    RecordType = "NS"
	RecordTXT   RecordType = "TXT"
	RecordCAA   RecordType = "CAA"
	RecordSOA   RecordType = "SOA"
	RecordPTR   RecordType = "PTR"
	RecordSRV   RecordType = "SRV"
)

func (r RecordType) Valid() bool {
	switch r {
	case RecordA, RecordAAAA, RecordCNAME, RecordMX, RecordNS, RecordTXT,
		RecordCAA, RecordSOA, RecordPTR, RecordSRV:
		return true
	default:
		return false
	}
}

// AllRecordTypes is the default collection set for the dns stage.
var AllRecordTypes = []RecordType{
	RecordA, RecordAAAA, RecordCNAME, RecordMX, RecordNS, RecordTXT, RecordCAA, RecordSOA,
}

// DNSRecord is a single collected DNS record.
type DNSRecord struct {
	Name     string     `json:"name"`
	Type     RecordType `json:"type"`
	Value    string     `json:"value"`
	TTL      uint32     `json:"ttl,omitempty"`
	Priority uint16     `json:"priority,omitempty"`
	Source   string     `json:"source,omitempty"`
	Observed time.Time  `json:"observed_at"`
}

// RecordHash is a stable identity for a DNS record, used for dedup.
func (r DNSRecord) RecordHash() string {
	sum := sha256.Sum256([]byte(strings.ToLower(r.Name) + "|" + string(r.Type) + "|" + strings.ToLower(r.Value)))
	return hex.EncodeToString(sum[:16])
}

// DNSResult aggregates everything learned about one hostname via DNS.
type DNSResult struct {
	Name      string       `json:"name"`
	Records   []DNSRecord  `json:"records"`
	IPs       []netip.Addr `json:"ips"`
	CNAMEs    []string     `json:"cnames"`
	Resolved  bool         `json:"resolved"`
	Dangling  bool         `json:"dangling_candidate"`
	Truncated bool         `json:"truncated"`
	// Unconnectable lists addresses the name resolved to that the scope engine
	// refused. They are observations, not targets: a public name pointing at a
	// private or metadata address is a takeover or rebinding signal, and nothing
	// downstream may treat these as somewhere to connect.
	Unconnectable []string  `json:"unconnectable,omitempty"`
	Errors        []string  `json:"errors,omitempty"`
	Observed      time.Time `json:"observed_at"`
}

// SecurityPosture summarises the security-relevant DNS configuration of a zone.
type SecurityPosture struct {
	HasSPF      bool     `json:"has_spf"`
	HasDMARC    bool     `json:"has_dmarc"`
	HasDKIMHint bool     `json:"has_dkim_hint"`
	HasCAA      bool     `json:"has_caa"`
	HasDNSSEC   bool     `json:"has_dnssec"`
	HasMX       bool     `json:"has_mx"`
	Notes       []string `json:"notes,omitempty"`
}

// HTTPSvc is the normalized record of one probed HTTP endpoint.
type HTTPSvc struct {
	URL           string               `json:"url"`
	InputURL      string               `json:"input_url,omitempty"`
	FinalURL      string               `json:"final_url,omitempty"`
	Method        string               `json:"method,omitempty"`
	StatusCode    int                  `json:"status_code"`
	Status        string               `json:"status,omitempty"`
	Title         string               `json:"title,omitempty"`
	Server        string               `json:"server,omitempty"`
	ContentType   string               `json:"content_type,omitempty"`
	ContentLength int64                `json:"content_length"`
	BodyHash      string               `json:"body_hash,omitempty"`
	HeaderHash    string               `json:"header_hash,omitempty"`
	Redirects     []Redirect           `json:"redirects,omitempty"`
	Technologies  []string             `json:"technologies,omitempty"`
	IPs           []string             `json:"ips,omitempty"`
	CNAME         string               `json:"cname,omitempty"`
	WebServer     string               `json:"web_server,omitempty"`
	CSP           string               `json:"csp,omitempty"`
	Location      string               `json:"location,omitempty"`
	Tech          []string             `json:"tech,omitempty"`
	TLS           *TLSInfo             `json:"tls,omitempty"`
	ElapsedMS     int64                `json:"elapsed_ms,omitempty"`
	Security      SecurityHeaderReport `json:"security_headers"`
	Observed      time.Time            `json:"observed_at"`
}

// Redirect is a single hop in a redirect chain.
type Redirect struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	InScope  bool   `json:"in_scope"`
	// Blocked records that the scope engine refused this hop, so the chain was
	// cut here and the destination was never requested.
	Blocked bool   `json:"blocked,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// TLSInfo holds non-secret TLS metadata. Certificate blobs are intentionally
// excluded; only subject/SAN/dates and protocol/cipher metadata are kept.
type TLSInfo struct {
	Version            string    `json:"version"`
	CipherSuite        string    `json:"cipher_suite,omitempty"`
	Subject            string    `json:"subject,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	Expired            bool      `json:"expired"`
	SelfSigned         bool      `json:"self_signed"`
	SANs               []string  `json:"sans,omitempty"`
	WildcardSANPresent bool      `json:"wildcard_san_present"`
	// NegotiatedProtocol is the ALPN protocol, if any.
	NegotiatedProtocol string `json:"alpn,omitempty"`
	// Fingerprint is the SHA-256 of the DER certificate (public data only).
	Fingerprint string `json:"fingerprint_sha256,omitempty"`
}

// SecurityHeaderReport captures presence and quality of standard headers.
type SecurityHeaderReport struct {
	Present map[string]string `json:"present,omitempty"`
	Missing []string          `json:"missing,omitempty"`
	Weak    []string          `json:"weak,omitempty"`
	Notes   []string          `json:"notes,omitempty"`
}

// Parameter is a discovered request parameter.
type Parameter struct {
	Name        string    `json:"name"`
	Kind        ParamKind `json:"kind"`
	Source      string    `json:"source,omitempty"`
	URL         string    `json:"url,omitempty"`
	Interesting bool      `json:"interesting,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Reflected   bool      `json:"reflected,omitempty"`
	Observed    time.Time `json:"observed_at"`
}

// ParamKind enumerates where a parameter was found.
type ParamKind string

const (
	ParamQuery  ParamKind = "query"
	ParamPath   ParamKind = "path"
	ParamForm   ParamKind = "form"
	ParamJSON   ParamKind = "json"
	ParamHeader ParamKind = "header"
	ParamCookie ParamKind = "cookie"
)

// ParamFingerprint is the stable dedup key for a parameter.
func (p Parameter) ParamFingerprint() string {
	sum := sha256.Sum256([]byte(strings.ToLower(string(p.Kind)) + "|" + p.Name + "|" + strings.ToLower(p.URL)))
	return hex.EncodeToString(sum[:16])
}

// Endpoint is a discovered attack surface entry.
type Endpoint struct {
	URL         string       `json:"url"`
	Method      string       `json:"method,omitempty"`
	Kind        EndpointKind `json:"kind"`
	Source      string       `json:"source"`
	Depth       int          `json:"depth"`
	StatusCode  int          `json:"status_code,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	Parameters  []Parameter  `json:"parameters,omitempty"`
	Observed    time.Time    `json:"observed_at"`
}

// EndpointKind classifies how an endpoint was discovered.
type EndpointKind string

const (
	EndpointLink     EndpointKind = "link"
	EndpointForm     EndpointKind = "form"
	EndpointScript   EndpointKind = "script"
	EndpointSitemap  EndpointKind = "sitemap"
	EndpointRobots   EndpointKind = "robots"
	EndpointRedirect EndpointKind = "redirect"
	EndpointJS       EndpointKind = "javascript"
	EndpointJSON     EndpointKind = "json"
	EndpointProbe    EndpointKind = "probe"
)

// SortParams returns a deterministic ordering for parameters.
func SortParams(in []Parameter) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Kind != in[j].Kind {
			return in[i].Kind < in[j].Kind
		}
		if in[i].URL != in[j].URL {
			return in[i].URL < in[j].URL
		}
		return in[i].Name < in[j].Name
	})
}
