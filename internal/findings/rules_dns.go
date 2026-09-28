package findings

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// dnsRules reports on mail and certificate-authority DNS hygiene, plus the
// asset inventory that passive discovery produces.
//
// None of these are remotely exploitable. They matter because each one is a
// precondition that some other attack depends on: absent DMARC and a
// permissive SPF are what make domain spoofing convincing, and absent CAA is
// what lets anyone with access to a cloud account mint a certificate for the
// domain.
func dnsRules() []Rule {
	return []Rule{
		{
			ID:          RuleDNSMissingSPF,
			Title:       "Domain publishes no SPF record",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"dns", "email"},
			Description: "The domain has no SPF record, so a receiving mail server has no published list of hosts permitted to send mail as this domain.",
			Impact:      "Receivers fall back to heuristics, and an attacker who can send from an unrelated host can often make mail appear to come from this domain.",
			Remediation: "Publish an SPF record listing every sending host, and keep it to ten lookups or fewer.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, p := range in.Posture {
					if p.HasSPF || !p.HasMX {
						// Without an MX there is nowhere for mail to be
						// delivered, so SPF has nothing to protect.
						continue
					}
					out = append(out, Result{
						Asset:   in.Asset,
						Summary: fmt.Sprintf("%s accepts mail but publishes no SPF record", in.Asset),
						Data:    map[string]string{"zone": in.Asset, "missing": "spf"},
					})
				}
				return out
			},
		},
		{
			ID:          RuleDNSPermissiveSPF,
			Title:       "SPF record authorises every host",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"dns", "email"},
			Description: "The domain's SPF record ends in `all`, or includes `+all`, which authorises any host on the internet to send mail as this domain.",
			Impact:      "Anyone who can send an email from anywhere can spoof mail from the domain, which is the basis of executive impersonation and invoice fraud.",
			Remediation: "Replace `+all` with `-all` once every legitimate sender is listed, then monitor with `~all` while the list is being proven.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, d := range in.DNS {
					for _, rec := range d.Records {
						if rec.Type != models.RecordTXT {
							continue
						}
						if !permissiveSPF(rec.Value) {
							continue
						}
						out = append(out, Result{
							Asset:   d.Name,
							Summary: fmt.Sprintf("%s publishes a permissive SPF record: %s", d.Name, truncate(rec.Value, 120)),
							Data: map[string]string{
								"zone":      d.Name,
								"spf":       rec.Value,
								"mechanism": strings.TrimSpace(rec.Value),
							},
						})
					}
				}
				return out
			},
		},
		{
			ID:          RuleDNSMissingDMARC,
			Title:       "Domain publishes no DMARC record",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"dns", "email"},
			Description: "The domain publishes no DMARC record, so a receiving server has no published instruction on what to do with mail that fails SPF or DKIM.",
			Impact:      "Spoofed mail is neither rejected nor quarantined. Without DMARC there is also no aggregate report showing who is attempting to spoof the domain.",
			Remediation: "Publish a DMARC record at `_dmarc` starting with `p=none`, review the aggregate reports, then move to `p=quarantine` and finally `p=reject`.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, p := range in.Posture {
					if p.HasDMARC || !p.HasMX {
						continue
					}
					out = append(out, Result{
						Asset:   in.Asset,
						Summary: fmt.Sprintf("%s accepts mail but publishes no DMARC record", in.Asset),
						Data:    map[string]string{"zone": in.Asset, "missing": "dmarc"},
					})
				}
				return out
			},
		},
		{
			ID:          RuleDNSMissingCAA,
			Title:       "Domain publishes no CAA record",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"dns", "tls"},
			Description: "The domain publishes no CAA record, so any publicly trusted certificate authority is permitted to issue a certificate for it.",
			Impact:      "It lowers the cost of obtaining a trusted certificate for the domain, which matters once an attacker has any other way to take over a related resource.",
			Remediation: "Publish a CAA record naming the authorities that should be allowed to issue for the domain.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc8659"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, p := range in.Posture {
					if p.HasCAA {
						continue
					}
					sev := models.SeverityInformational
					if p.HasMX {
						// Mail domains are impersonation targets, and a CAA
						// record here is a cheap control against certificate
						// mis-issue on the mail domain itself.
						sev = models.SeverityLow
					}
					out = append(out, Result{
						Asset:    in.Asset,
						Severity: &sev,
						Summary:  fmt.Sprintf("%s publishes no CAA record", in.Asset),
						Data:     map[string]string{"zone": in.Asset, "missing": "caa"},
					})
				}
				return out
			},
		},
		{
			ID:          RuleDNSSubdomain,
			Title:       "Subdomain resolves within the engagement scope",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceMedium,
			Tags:        []string{"dns", "inventory"},
			Description: "A name inside the engagement scope resolves to an address, which means the name exists and is reachable. Whether it is in the client's inventory is a question for a human.",
			Impact:      "Undeclared and forgotten subdomains are the usual first step in an attack, because they are less monitored and frequently share infrastructure with production.",
			Remediation: "Reconcile the discovered names against the client's asset inventory and decommission or formally adopt the remainder.",
			References:  []string{"https://crt.sh/"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, d := range in.DNS {
					if d.Name == "" || strings.EqualFold(d.Name, in.Asset) {
						continue
					}
					conn := false
					for _, rec := range d.Records {
						if rec.Type == models.RecordA || rec.Type == models.RecordAAAA {
							conn = true
							break
						}
					}
					if !conn {
						continue
					}
					out = append(out, Result{
						Asset:   d.Name,
						Summary: fmt.Sprintf("%s resolves to a reachable address", d.Name),
						Data: map[string]string{
							"name":      d.Name,
							"addresses": fmt.Sprintf("%d", countAddressRecords(d)),
							"truncated": fmt.Sprintf("%t", d.Truncated),
						},
					})
				}
				sort.SliceStable(out, func(i, j int) bool { return out[i].Asset < out[j].Asset })
				return out
			},
		},
		{
			ID:          RuleDNSUnconnectableTarget,
			Title:       "A name in scope resolves to an address that must not be contacted",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceMedium,
			Tags:        []string{"dns", "takeover"},
			Description: "The name resolves, but the addresses it points at are private, link-local, loopback or cloud metadata addresses that the toolkit refuses to connect to. A public name pointing into one of those ranges is either a takeover opportunity or a DNS rebinding setup.",
			Impact:      "A dangling record that still resolves can be claimed by whoever controls the target service. A rebinding record can turn a permitted request into one aimed at an address the operator believes is off-limits.",
			Remediation: "Remove the record if the service is decommissioned, or restore the intended target. Confirm the ownership of the service at the address before assuming it is claimable.",
			References:  []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			ManualVerification: []string{
				"Determine which service the address belongs to and whether that service is still in use.",
				"Establish who controls it before any claim is made; do not attempt to register or claim the resource.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, d := range in.DNS {
					if len(d.Unconnectable) == 0 {
						continue
					}
					sev := models.SeverityMedium
					summary := fmt.Sprintf("%s resolves to %d address(es) that are not publicly connectable", d.Name, len(d.Unconnectable))
					if d.Dangling {
						sev = models.SeverityHigh
						summary = fmt.Sprintf("%s is a dangling record: it still resolves but the target no longer answers", d.Name)
					}
					out = append(out, Result{
						Asset:    d.Name,
						Severity: &sev,
						Summary:  summary,
						Data: map[string]string{
							"name":          d.Name,
							"unconnectable": strings.Join(d.Unconnectable, ","),
							"dangling":      fmt.Sprintf("%t", d.Dangling),
						},
					})
				}
				sort.SliceStable(out, func(i, j int) bool { return out[i].Asset < out[j].Asset })
				return out
			},
		},
	}
}

// permissiveSPF reports whether a TXT record authorises every host. Both the
// legacy `v=spf1 ... +all` form and the bare `all` mechanism are treated as
// permissive, because an operator who wrote `all` meant exactly that.
func permissiveSPF(v string) bool {
	fields := strings.Fields(strings.ToLower(v))
	isSPF := false
	for _, f := range fields {
		if strings.HasPrefix(f, "v=spf1") {
			isSPF = true
			continue
		}
	}
	if !isSPF {
		return false
	}
	for _, f := range fields {
		if f == "all" || f == "+all" {
			return true
		}
	}
	return false
}

func countAddressRecords(d models.DNSResult) int {
	n := 0
	for _, rec := range d.Records {
		if rec.Type == models.RecordA || rec.Type == models.RecordAAAA {
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
