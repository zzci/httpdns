package httpdns

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

const nanoidAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
const subdomainLength = 8
const apiKeyLength = 32

// GenerateAPIKey creates a random API key (32-char lowercase alphanumeric).
func GenerateAPIKey() string {
	b := make([]byte, apiKeyLength)
	max := big.NewInt(int64(len(nanoidAlphabet)))
	for i := range b {
		n, _ := rand.Int(rand.Reader, max)
		b[i] = nanoidAlphabet[n.Int64()]
	}
	return string(b)
}

// GenerateSubdomain creates a deterministic subdomain from username and domain.
// The same username+domain always produces the same subdomain, so even if
// the database is lost, CNAME records don't need to change.
func GenerateSubdomain(username, domain string) string {
	input := strings.ToLower(username) + ":" + strings.ToLower(domain)
	hash := sha256.Sum256([]byte(input))
	hexStr := hex.EncodeToString(hash[:])
	// Take first 8 chars — hex only uses 0-9a-f, which is a subset of nanoidAlphabet
	return hexStr[:subdomainLength]
}

// InternalDomain returns the full internal domain for a subdomain under the base domain.
// Example: subdomain "a7x9k2", baseDomain "dns.example.com" -> "a7x9k2.dns.example.com"
func InternalDomain(subdomain, baseDomain string) string {
	baseDomain = strings.TrimSuffix(strings.TrimSpace(baseDomain), ".")
	return subdomain + "." + baseDomain
}

// ExtractDomainFromFQDN strips _acme-challenge. prefix and trailing dot.
// Example: "_acme-challenge.example.com." -> "example.com"
func ExtractDomainFromFQDN(fqdn string) string {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.TrimPrefix(fqdn, "_acme-challenge.")
	return fqdn
}

// ExtractSubdomainFromFQDN extracts the nanoid subdomain if the FQDN is under the base domain.
// Example: "r0hc4bc6.s.dnsall.com." with baseDomain "s.dnsall.com" -> "r0hc4bc6", true
// Returns empty string and false if the FQDN is not under the base domain.
func ExtractSubdomainFromFQDN(fqdn, baseDomain string) (string, bool) {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	fqdn = strings.TrimSuffix(fqdn, ".")
	baseDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(baseDomain), "."))
	suffix := "." + baseDomain
	if strings.HasSuffix(fqdn, suffix) {
		sub := strings.TrimSuffix(fqdn, suffix)
		if sub != "" && !strings.Contains(sub, ".") {
			return sub, true
		}
	}
	return "", false
}
