package scope

import "strings"

// publicSuffixes is a deliberately small, offline list of suffixes that must
// never be wildcarded. A full Public Suffix List is not vendored because the
// toolkit must work without network access at load time; the entries below
// cover the multi-label suffixes most likely to appear in a mistaken scope file
// together with the rule that a wildcard parent must contain at least one dot.
var publicSuffixes = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {},
	"info": {}, "biz": {}, "io": {}, "co": {}, "dev": {}, "app": {}, "ai": {},
	"cloud": {}, "online": {}, "site": {}, "tech": {}, "xyz": {}, "me": {},
	"cc": {}, "tv": {}, "us": {}, "uk": {}, "de": {}, "fr": {}, "jp": {},
	"cn": {}, "in": {}, "ru": {}, "br": {}, "au": {}, "ca": {}, "it": {},
	"es": {}, "nl": {}, "se": {}, "ch": {}, "at": {}, "be": {}, "pl": {},
	"eu": {}, "asia": {}, "name": {}, "pro": {}, "mobi": {}, "tel": {},
	"travel": {}, "jobs": {}, "cat": {}, "post": {}, "test": {},
	"localhost": {}, "local": {}, "internal": {}, "intranet": {}, "lan": {},
	"home": {}, "corp": {}, "example": {}, "invalid": {}, "onion": {},
	// multi-label public suffixes
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "gov.uk": {}, "me.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"co.jp": {}, "or.jp": {}, "ne.jp": {}, "ac.jp": {}, "go.jp": {},
	"co.nz": {}, "net.nz": {}, "org.nz": {}, "govt.nz": {},
	"co.in": {}, "net.in": {}, "org.in": {}, "gen.in": {}, "firm.in": {},
	"com.br": {}, "net.br": {}, "org.br": {}, "gov.br": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {},
	"co.za": {}, "org.za": {}, "web.za": {},
	"com.mx": {}, "com.ar": {}, "com.tr": {}, "com.sg": {}, "com.hk": {},
	"co.kr": {}, "or.kr": {}, "ne.kr": {}, "re.kr": {},
}

// isPublicSuffix reports whether host is a public (or reserved) suffix, i.e. a
// name that must never be wildcarded or used as a wildcard parent.
func isPublicSuffix(host string) bool {
	if _, ok := publicSuffixes[host]; ok {
		return true
	}
	// Anything with a single label is at least as dangerous as a public suffix.
	return !strings.Contains(host, ".")
}
