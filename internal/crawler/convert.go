package crawler

import (
	"net/http"

	"github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// ServiceFromResponse converts a client response into the normalized service
// record used by storage, findings and reporting.
func ServiceFromResponse(r *httpclient.Response, inputURL string, depth int) models.HTTPSvc {
	svc := models.HTTPSvc{
		URL:           r.URL,
		InputURL:      inputURL,
		FinalURL:      r.FinalURL,
		Method:        r.Method,
		StatusCode:    r.StatusCode,
		Status:        r.Status,
		Title:         r.Title,
		Server:        firstOrEmpty(r.Header["server"]),
		ContentType:   r.ContentType,
		ContentLength: r.ContentLength,
		BodyHash:      r.BodyHash,
		HeaderHash:    r.HeaderHash,
		Observed:      r.Timestamp,
		ElapsedMS:     r.Elapsed.Milliseconds(),
		IPs:           r.IPs,
	}
	if svc.Server == "" {
		svc.Server = firstOrEmpty(r.Header["x-powered-by"])
	}
	if len(r.Redirects) > 0 {
		svc.Redirects = make([]models.Redirect, 0, len(r.Redirects))
		for _, h := range r.Redirects {
			svc.Redirects = append(svc.Redirects, models.Redirect{
				From: h.From, To: h.To, Status: h.Status, Location: h.Location, InScope: h.InScope,
			})
		}
	}
	if r.TLS != nil {
		svc.TLS = &models.TLSInfo{
			Version:            r.TLS.Version,
			CipherSuite:        r.TLS.CipherSuite,
			Subject:            r.TLS.Subject,
			Issuer:             r.TLS.Issuer,
			SerialNumber:       r.TLS.Serial,
			NotBefore:          r.TLS.NotBefore,
			NotAfter:           r.TLS.NotAfter,
			Expired:            r.TLS.Expired,
			SelfSigned:         r.TLS.SelfSigned,
			SANs:               r.TLS.SANs,
			WildcardSANPresent: r.TLS.WildcardSAN,
			NegotiatedProtocol: r.TLS.ALPN,
			Fingerprint:        r.TLS.Fingerprint,
		}
	}
	return svc
}

func firstOrEmpty(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

var _ = http.MethodGet
