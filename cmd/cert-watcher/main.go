package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	renewalThreshold  = 120 * time.Hour // 5 days
	replacedSuffixFmt = "20060102150405"
)

func main() {
	// JSON slog for journald
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	var pemPathFlag, wellKnownHostFlag, webServiceFlag string
	flag.StringVar(&pemPathFlag, "pem", "", "path to PEM file (leaf/fullchain); its basename is used to form the well-known URL")
	flag.StringVar(&wellKnownHostFlag, "well-known", "", "host or IP (no scheme/path); e.g. 1.2.3.4 or example.com")
	flag.StringVar(&webServiceFlag, "web-service", "", "optional: service to reload (e.g. nginx, apache2, httpd)")
	flag.Parse()

	// env fallbacks
	pemPath := firstNonEmpty(pemPathFlag, os.Getenv("PEM"))
	wellKnownHost := firstNonEmpty(wellKnownHostFlag, os.Getenv("WELL_KNOWN"))
	webService := firstNonEmpty(webServiceFlag, os.Getenv("WEB_SERVICE"))

	if strings.TrimSpace(pemPath) == "" || strings.TrimSpace(wellKnownHost) == "" {
		slog.Error("missing required parameters", "pem", pemPath, "well_known_host", wellKnownHost)
		flag.Usage()
		os.Exit(2)
	}

	// Manufacture URL from host + PEM basename
	wkURL, err := buildWellKnownURL(pemPath, wellKnownHost)
	if err != nil {
		slog.Error("build well-known URL failed", "error", err)
		os.Exit(2)
	}
	slog.Info("using well-known URL", "url", wkURL)

	// Bootstrap if PEM missing
	if _, err := os.Stat(pemPath); errors.Is(err, os.ErrNotExist) {
		slog.Info("pem not found; bootstrapping from well-known", "pem", pemPath)
		if err := bootstrapFromWellKnown(pemPath, wkURL); err != nil {
			slog.Error("bootstrap failed", "error", err)
			os.Exit(1)
		}
		if err := reloadServices(webService); err != nil {
			slog.Warn("service reload after bootstrap", "error", err)
		}
		// continue to policy check (harmless if it just says “nothing to do”)
		os.Exit(0)
	}

	// Single check then exit (one-shot)
	if err := checkOnce(pemPath, wkURL, webService); err != nil {
		slog.Warn("checkOnce", "error", err)
		os.Exit(1)
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return strings.TrimSpace(b)
}

// buildWellKnownURL constructs:
//
//	http://<host>:47900/.well-known/ssl/<basename(pemPath)>
//
// It tolerates users accidentally passing scheme or a host:port, and normalizes to :47900.
func buildWellKnownURL(pemPath, hostInput string) (string, error) {
	base := filepath.Base(pemPath)
	if base == "." || base == "/" || base == "" {
		return "", fmt.Errorf("invalid pem basename derived from %q", pemPath)
	}

	host := strings.TrimSpace(hostInput)

	// If a scheme slipped in, parse and extract host.
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err == nil && u.Host != "" {
			host = u.Host
		}
	}

	// Strip any provided port; we will force 47900
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}

	// Join host + fixed port 47900 (handles IPv6 correctly)
	hostPort := net.JoinHostPort(host, "47900")

	// Build final URL
	return (&url.URL{
		Scheme: "http",
		Host:   hostPort,
		Path:   "/.well-known/ssl/" + base,
	}).String(), nil
}

func bootstrapFromWellKnown(pemPath, wellKnownURL string) error {
	body, err := httpGet(wellKnownURL, 30*time.Second)
	if err != nil {
		return fmt.Errorf("fetch well-known: %w", err)
	}
	certs, err := parsePEMCerts(body)
	if err != nil {
		return fmt.Errorf("parse well-known pem: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("no certificates found at well-known")
	}
	leaf := pickLeaf(certs)

	if err := os.MkdirAll(filepath.Dir(pemPath), 0o755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", filepath.Dir(pemPath), err)
	}
	if err := replacePEMFile(pemPath, body); err != nil {
		return fmt.Errorf("install pem: %w", err)
	}
	slog.Info("bootstrapped certificate",
		"cn", leaf.Subject.CommonName,
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"path", pemPath)
	return nil
}

func checkOnce(pemPath, wellKnownURL, webService string) error {
	curCert, _, err := loadLeafCertFromPEMFile(pemPath)
	if err != nil {
		return fmt.Errorf("load current cert: %w", err)
	}

	until := time.Until(curCert.NotAfter).Round(time.Second)
	slog.Info("current certificate",
		"cn", curCert.Subject.CommonName,
		"not_after", curCert.NotAfter.UTC().Format(time.RFC3339),
		"expires_in", until.String())

	if until > renewalThreshold {
		slog.Info("certificate not within renewal threshold; nothing to do",
			"threshold", renewalThreshold.String())
		return nil
	}

	body, err := httpGet(wellKnownURL, 30*time.Second)
	if err != nil {
		return fmt.Errorf("fetch well-known: %w", err)
	}
	newCerts, err := parsePEMCerts(body)
	if err != nil {
		return fmt.Errorf("parse new PEM: %w", err)
	}
	if len(newCerts) == 0 {
		return errors.New("no certificates found in well-known response")
	}
	newLeaf := pickLeaf(newCerts)

	// Validate name match and expiry improvement
	if !newMatchesCurrent(curCert, newLeaf) {
		return fmt.Errorf("name mismatch: current CN %q vs new cert names",
			curCert.Subject.CommonName)
	}
	if !newLeaf.NotAfter.After(curCert.NotAfter) {
		return fmt.Errorf("new cert not later: new %s <= current %s",
			newLeaf.NotAfter, curCert.NotAfter)
	}

	// Persist the entire response (verbatim)
	if err := replacePEMFile(pemPath, body); err != nil {
		return fmt.Errorf("replace pem: %w", err)
	}
	slog.Info("certificate replaced",
		"old_not_after", curCert.NotAfter.UTC().Format(time.RFC3339),
		"new_not_after", newLeaf.NotAfter.UTC().Format(time.RFC3339),
		"path", pemPath)

	if err := reloadServices(webService); err != nil {
		slog.Warn("service reload", "error", err)
	}
	return nil
}

func httpGet(rawURL string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s => %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return io.ReadAll(resp.Body)
}

func parsePEMCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func loadLeafCertFromPEMFile(path string) (*x509.Certificate, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var leaf *x509.Certificate
	var leafDER []byte
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if !c.IsCA && leaf == nil {
			leaf = c
			leafDER = block.Bytes
			continue
		}
		if leaf == nil {
			leaf = c
			leafDER = block.Bytes
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("no certificate block found in PEM file")
	}
	return leaf, leafDER, nil
}

func pickLeaf(certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if !c.IsCA {
			return c
		}
	}
	return certs[0]
}

func newMatchesCurrent(current *x509.Certificate, newC *x509.Certificate) bool {
	curCN := strings.TrimSpace(current.Subject.CommonName)
	if curCN == "" {
		return false
	}
	candidates := make([]string, 0, 1+len(newC.DNSNames))
	if newC.Subject.CommonName != "" {
		candidates = append(candidates, newC.Subject.CommonName)
	}
	candidates = append(candidates, newC.DNSNames...)
	for _, name := range candidates {
		if dnsMatch(name, curCN) || dnsMatch(curCN, name) {
			return true
		}
	}
	return false
}

// simple DNSName match with single-label wildcard support
func dnsMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if host == suffix {
			return false
		}
		return strings.HasSuffix(host, "."+suffix)
	}
	return false
}

func replacePEMFile(origPath string, responseBody []byte) error {
	dir := filepath.Dir(origPath)
	base := filepath.Base(origPath)
	ts := time.Now().Format(replacedSuffixFmt)

	backup := filepath.Join(dir, fmt.Sprintf("%s.replaced-%s", base, ts))
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%s", base, ts))

	if err := os.Rename(origPath, backup); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rename old->backup: %w", err)
		}
	}
	if err := os.WriteFile(tmp, responseBody, 0o644); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := fsyncPath(tmp); err != nil {
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := os.Rename(tmp, origPath); err != nil {
		return fmt.Errorf("rename temp->orig: %w", err)
	}
	_ = fsyncPath(dir) // best effort
	return nil
}

func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func reloadServices(webService string) error {
	if strings.TrimSpace(webService) != "" {
		return reloadOne(webService)
	}
	// autodetect & reload active ones
	candidates := []string{"nginx", "apache2", "httpd", "caddy", "lighttpd", "haproxy"}
	var errs []string
	for _, svc := range candidates {
		if !isActiveUnit(svc) {
			continue
		}
		if err := reloadOne(svc); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", svc, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isActiveUnit(svc string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", svc)
	return cmd.Run() == nil
}

func reloadOne(svc string) error {
	slog.Info("reloading service", "service", svc)
	cmd := exec.Command("systemctl", "reload", svc)
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("reload failed; trying restart", "service", svc, "error", err, "out", strings.TrimSpace(string(out)))
		cmd = exec.Command("systemctl", "restart", svc)
		out, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("restart failed: %v (out: %s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
