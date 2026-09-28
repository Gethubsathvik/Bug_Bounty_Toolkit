package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// timeFormat is the single timestamp format used in the database. Storing a
// fixed layout keeps lexicographic ordering equal to chronological ordering,
// which the indexes rely on.
const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func fmtTime(t time.Time) string {
	if t.IsZero() {
		t = nowUTC()
	}
	return t.UTC().Format(timeFormat)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{timeFormat, time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func unmarshalJSON(s string, v any) {
	if s == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}

// ---------------------------------------------------------------- domains ---

// UpsertDomain records a domain and returns its row id.
func (s *Store) UpsertDomain(ctx context.Context, name, source string, meta map[string]string) (int64, error) {
	metaJSON, _ := jsonMap(meta)
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		err := tx.QueryRowContext(ctx, `
			INSERT INTO domains (name, source, first_seen, last_seen, meta)
			VALUES (?,?,?,?,?)
			ON CONFLICT(name) DO UPDATE SET
				last_seen = excluded.last_seen,
				source    = COALESCE(excluded.source, domains.source),
				meta      = COALESCE(excluded.meta, domains.meta)
			RETURNING id`, name, nullString(source), now, now, nullString(metaJSON)).Scan(&id)
		if err != nil {
			return fmt.Errorf("upserting domain %q: %w", name, err)
		}
		return nil
	})
	return id, err
}

// UpsertSubdomain records a subdomain. Names are canonicalized by the caller;
// anything that is not a strict subdomain of a stored domain is stored as a
// domain instead so that the graph stays consistent.
func (s *Store) UpsertSubdomain(ctx context.Context, name, source string, resolved bool, domainID int64) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		err := tx.QueryRowContext(ctx, `
			INSERT INTO subdomains (name, domain, source, resolved, first_seen, last_seen)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(name) DO UPDATE SET
				last_seen = excluded.last_seen,
				resolved  = MAX(subdomains.resolved, excluded.resolved),
				source    = COALESCE(subdomains.source, excluded.source),
				domain    = COALESCE(subdomains.domain, excluded.domain)
			RETURNING id`, name, nullInt64(domainID), nullString(source), resolved, now, now).Scan(&id)
		if err != nil {
			return fmt.Errorf("upserting subdomain %q: %w", name, err)
		}
		return nil
	})
	return id, err
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// UpsertIP records an address.
func (s *Store) UpsertIP(ctx context.Context, address, scopeRule string, meta map[string]string) (int64, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q: %w", address, err)
	}
	metaJSON, _ := jsonMap(meta)
	version := 6
	if addr.Is4() {
		version = 4
	}
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		return tx.QueryRowContext(ctx, `
			INSERT INTO ips (address, version, scope_rule, first_seen, last_seen, meta)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
				last_seen   = excluded.last_seen,
				scope_rule  = COALESCE(excluded.scope_rule, ips.scope_rule),
				meta        = COALESCE(excluded.meta, ips.meta)
			RETURNING id`, addr.String(), version, nullString(scopeRule), now, now, nullString(metaJSON)).Scan(&id)
	})
	return id, err
}

// UpsertService records an HTTP service.
func (s *Store) UpsertService(ctx context.Context, svc models.HTTPSvc) (int64, error) {
	meta := map[string]string{
		"content_length": fmtInt64(svc.ContentLength),
		"body_hash":      svc.BodyHash,
		"redirect_count": fmtInt(len(svc.Redirects)),
		"final_url":      svc.FinalURL,
		"csp_present":    boolStr(svc.CSP != ""),
		"elapsed_ms":     fmtInt64(svc.ElapsedMS),
	}
	if svc.CNAME != "" {
		meta["cname"] = svc.CNAME
	}
	if svc.WebServer != "" {
		meta["web_server"] = svc.WebServer
	}
	metaJSON, _ := jsonMap(meta)
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		return tx.QueryRowContext(ctx, `
			INSERT INTO services (kind, url, host, port, scheme, status_code, title, first_seen, last_seen, meta)
			VALUES ('http',?,?,?,?,?,?,?,?,?)
			ON CONFLICT(url) DO UPDATE SET
				last_seen   = excluded.last_seen,
				status_code = excluded.status_code,
				title       = COALESCE(NULLIF(excluded.title,''), services.title),
				meta        = excluded.meta
			RETURNING id`,
			svc.URL, hostOf(svc.URL), portOf(svc.URL), schemeOf(svc.URL),
			nullInt(svc.StatusCode), nullString(svc.Title), now, now, nullString(metaJSON)).Scan(&id)
	})
	return id, err
}

// UpsertURL records a discovered URL.
func (s *Store) UpsertURL(ctx context.Context, url string, serviceID int64, kind string, status int, depth int, source string) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		return tx.QueryRowContext(ctx, `
			INSERT INTO urls (url, service, kind, status_code, depth, source, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?)
			ON CONFLICT(url) DO UPDATE SET
				last_seen   = excluded.last_seen,
				status_code = COALESCE(excluded.status_code, urls.status_code),
				depth       = MIN(urls.depth, excluded.depth),
				source      = COALESCE(urls.source, excluded.source)
			RETURNING id`, url, nullInt64(serviceID), nullString(kind), nullInt(status), depth, nullString(source), now, now).Scan(&id)
	})
	return id, err
}

// UpsertEndpoint records an attack-surface entry.
func (s *Store) UpsertEndpoint(ctx context.Context, ep models.Endpoint, serviceID int64) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		return tx.QueryRowContext(ctx, `
			INSERT INTO endpoints (url, service, method, kind, source, depth, status_code, content_type, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(url) DO UPDATE SET
				last_seen    = excluded.last_seen,
				status_code  = COALESCE(excluded.status_code, endpoints.status_code),
				content_type = COALESCE(excluded.content_type, endpoints.content_type),
				depth        = MIN(endpoints.depth, excluded.depth),
				source       = COALESCE(endpoints.source, excluded.source)
			RETURNING id`, ep.URL, nullInt64(serviceID), nullString(ep.Method), string(ep.Kind),
			nullString(ep.Source), ep.Depth, nullInt(ep.StatusCode), nullString(ep.ContentType), now, now).Scan(&id)
	})
	return id, err
}

// UpsertParameter records a discovered parameter. Identical parameters seen at
// several URLs are stored once per (kind, name, url) fingerprint and merged.
func (s *Store) UpsertParameter(ctx context.Context, p models.Parameter, endpointID int64) (int64, error) {
	fp := p.ParamFingerprint()
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := fmtTime(nowUTC())
		return tx.QueryRowContext(ctx, `
			INSERT INTO parameters (fingerprint, name, kind, endpoint, url, source, interesting, reason, reflected, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(fingerprint) DO UPDATE SET
				last_seen   = excluded.last_seen,
				interesting = MAX(parameters.interesting, excluded.interesting),
				reflected   = MAX(parameters.reflected, excluded.reflected),
				reason      = COALESCE(parameters.reason, excluded.reason),
				endpoint    = COALESCE(parameters.endpoint, excluded.endpoint)
			RETURNING id`, fp, p.Name, string(p.Kind), nullInt64(endpointID), nullString(p.URL),
			nullString(p.Source), p.Interesting, nullString(p.Reason), p.Reflected, now, now).Scan(&id)
	})
	return id, err
}

// UpsertTechnology records a technology and links it to a service.
func (s *Store) UpsertTechnology(ctx context.Context, serviceID int64, name, version, category, confidence string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("technology name is empty")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var techID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO technologies (name, version, category, confidence)
			VALUES (?,?,?,?)
			ON CONFLICT(name, version) DO UPDATE SET
				category   = COALESCE(NULLIF(excluded.category,''), technologies.category),
				confidence = excluded.confidence
			RETURNING id`, name, version, category, confidence).Scan(&techID)
		if err != nil {
			return fmt.Errorf("upserting technology %q: %w", name, err)
		}
		if serviceID == 0 {
			return nil
		}
		_, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO service_technologies (service, technology) VALUES (?,?)`, serviceID, techID)
		return err
	})
}

// UpsertDNSRecord stores a DNS record, deduplicated on its content hash.
func (s *Store) UpsertDNSRecord(ctx context.Context, r models.DNSRecord) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO dns_records (hash, name, type, value, ttl, priority, source, observed_at)
			VALUES (?,?,?,?,?,?,?,?)
			ON CONFLICT(hash) DO UPDATE SET observed_at = excluded.observed_at`,
			r.RecordHash(), r.Name, string(r.Type), r.Value,
			nullInt(int(r.TTL)), nullInt(int(r.Priority)), nullString(r.Source), fmtTime(r.Observed))
		return err
	})
}

// SaveDNSResult stores every record of a resolution result.
func (s *Store) SaveDNSResult(ctx context.Context, res models.DNSResult) error {
	for _, r := range res.Records {
		if err := s.UpsertDNSRecord(ctx, r); err != nil {
			return err
		}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		// The records are written to their own table for relationship queries,
		// but they are also carried in the stored payload. Without that,
		// LoadDNSResult would return a result with the summary filled in and the
		// records silently missing, which is a lossy round trip that a resume
		// would then propagate.
		payload := marshalJSON(map[string]any{
			"ips": res.IPs, "cnames": res.CNAMEs, "resolved": res.Resolved,
			"dangling": res.Dangling, "errors": res.Errors, "records": res.Records,
			"truncated": res.Truncated, "unconnectable": res.Unconnectable,
			"observed": res.Observed,
		})
		_, err := tx.ExecContext(ctx, `
			INSERT INTO dns_postures (name, data, observed) VALUES (?,?,?)
			ON CONFLICT(name) DO UPDATE SET data = excluded.data, observed = excluded.observed`,
			res.Name, payload, fmtTime(res.Observed))
		return err
	})
}

// LoadDNSResult returns a previously stored resolution result.
func (s *Store) LoadDNSResult(ctx context.Context, name string) (models.DNSResult, bool, error) {
	var data, observed string
	err := s.db.QueryRowContext(ctx,
		`SELECT data, observed FROM dns_postures WHERE name = ?`, name).Scan(&data, &observed)
	if errors.Is(err, sql.ErrNoRows) {
		return models.DNSResult{}, false, nil
	}
	if err != nil {
		return models.DNSResult{}, false, err
	}
	var raw struct {
		IPs           []netip.Addr       `json:"ips"`
		CNAMEs        []string           `json:"cnames"`
		Resolved      bool               `json:"resolved"`
		Dangling      bool               `json:"dangling"`
		Truncated     bool               `json:"truncated"`
		Unconnectable []string           `json:"unconnectable"`
		Errors        []string           `json:"errors"`
		Records       []models.DNSRecord `json:"records"`
		Observed      time.Time          `json:"observed"`
	}
	unmarshalJSON(data, &raw)
	return models.DNSResult{
		Name: name, IPs: raw.IPs, CNAMEs: raw.CNAMEs, Resolved: raw.Resolved,
		Dangling: raw.Dangling, Truncated: raw.Truncated, Unconnectable: raw.Unconnectable,
		Errors: raw.Errors, Records: raw.Records, Observed: raw.Observed,
	}, true, nil
}

// SaveGraph persists the asset graph. It is written in one transaction so a
// partially stored graph is never observable.
func (s *Store) SaveGraph(ctx context.Context, g *models.Graph) error {
	nodes := g.Nodes("")
	edges := g.Edges()
	return s.tx(ctx, func(tx *sql.Tx) error {
		nodeStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO asset_nodes (kind, key, label, first_seen, last_seen, attrs)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(kind, key) DO UPDATE SET
				label      = COALESCE(NULLIF(excluded.label,''), asset_nodes.label),
				last_seen  = excluded.last_seen,
				attrs      = COALESCE(excluded.attrs, asset_nodes.attrs)`)
		if err != nil {
			return err
		}
		defer nodeStmt.Close()
		for _, n := range nodes {
			attrsJSON, _ := jsonMap(n.Attrs)
			if _, err := nodeStmt.ExecContext(ctx, string(n.Kind), n.Key, nullString(n.Label),
				fmtTime(n.First), fmtTime(n.Last), nullString(attrsJSON)); err != nil {
				return fmt.Errorf("saving node %s/%s: %w", n.Kind, n.Key, err)
			}
		}
		edgeStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO asset_edges (from_kind, from_key, rel, to_kind, to_key, attrs)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(from_kind, from_key, rel, to_kind, to_key) DO UPDATE SET attrs = excluded.attrs`)
		if err != nil {
			return err
		}
		defer edgeStmt.Close()
		for _, e := range edges {
			if _, err := edgeStmt.ExecContext(ctx, string(e.From), e.FromK, string(e.Rel),
				string(e.To), e.ToK, nullString(redact.Sanitize(e.Attrs))); err != nil {
				return fmt.Errorf("saving edge: %w", err)
			}
		}
		return nil
	})
}

// LoadGraph reads the persisted asset graph.
func (s *Store) LoadGraph(ctx context.Context) (*models.Graph, error) {
	g := models.NewGraph()
	rows, err := s.db.QueryContext(ctx, `SELECT kind, key, label, first_seen, last_seen, attrs FROM asset_nodes`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n models.Node
		var kind string
		// label and attrs are nullable columns: a node stored without a label or
		// without attributes scans as NULL, which cannot be read into a string.
		var label, attrs sql.NullString
		var first, last sql.NullString
		if err := rows.Scan(&kind, &n.Key, &label, &first, &last, &attrs); err != nil {
			rows.Close()
			return nil, err
		}
		n.Kind = models.NodeKind(kind)
		n.Label = label.String
		n.First = parseTime(first.String)
		n.Last = parseTime(last.String)
		unmarshalJSON(attrs.String, &n.Attrs)
		g.AddNode(n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	erows, err := s.db.QueryContext(ctx, `SELECT from_kind, from_key, rel, to_kind, to_key, attrs FROM asset_edges`)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var e models.Edge
		var fromKind, rel, toKind string
		var attrs sql.NullString
		if err := erows.Scan(&fromKind, &e.FromK, &rel, &toKind, &e.ToK, &attrs); err != nil {
			return nil, err
		}
		e.From, e.Rel, e.To = models.NodeKind(fromKind), models.EdgeRel(rel), models.NodeKind(toKind)
		e.Attrs = attrs.String
		g.AddEdge(e)
	}
	return g, erows.Err()
}

// ---------------------------------------------------------------- helpers ---

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		s = s[:i]
	}
	return strings.Trim(s, "[]")
}

func portOf(u string) int {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		var p int
		if _, err := fmt.Sscanf(s[i+1:], "%d", &p); err == nil {
			return p
		}
	}
	if strings.HasPrefix(u, "https://") {
		return 443
	}
	return 80
}

func schemeOf(u string) string {
	if strings.HasPrefix(u, "https://") {
		return "https"
	}
	return "http"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
