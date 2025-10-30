package main

import (
	"bytes"
	"context" // Required for graceful shutdown
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog" // Standard library structured logging
	"net"
	"net/http"
	"os"
	"os/signal" // Required for signal handling
	"strings"
	"sync"
	"syscall" // Required for SIGINT/SIGTERM
	"time"
)

// OID Definitions for ASN.1 Parsing
var oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
var oidCACaIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

// accessDescription mirrors the structure used to parse an AIA entry in ASN.1.
type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// Configuration for network operations and timing
const (
	maxChainDepth       = 5
	maxRetries          = 3
	initialDelay        = 1 * time.Second
	watcherInterval     = 30 * time.Minute
	refreshBeforeExpiry = 24 * time.Hour
	serverPort          = "47900"
	shutdownTimeout     = 10 * time.Second // Time allocated for graceful shutdown
)

// SSLCertManager holds the state of the managed certificate and provides thread-safe access.
type SSLCertManager struct {
	sync.RWMutex
	certPath string
	keyPath  string

	// Domain suffix required for client IP reverse lookup
	validClientDomain string

	// Managed state
	bundleName  string    // e.g., "example_com_bundle.pem"
	bundleFile  []byte    // The contents of the bundle file to serve (cert + intermediates + key)
	certModTime time.Time // Last known modification time of the cert file
	keyModTime  time.Time // Last known modification time of the key file
	minExpiry   time.Time // Earliest expiry time among all certs in the bundle

	// Fields for graceful shutdown
	server       *http.Server  // The HTTP server instance
	shutdownChan chan struct{} // Signal channel for the watcher routine
}

func main() {
	// Configure global structured logger (JSON output is common for systemd/log collectors)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// 1. Define flags
	certFileFlag := flag.String("cert", "", "Path to the server's PEM/CRT file (can be set by CERT env var).")
	keyFileFlag := flag.String("key", "", "Path to the server's private key file (can be set by KEY env var).")
	clientDomainFlag := flag.String("valid-client-domain", "", "Required domain suffix for client IP reverse lookup (can be set by VALID_CLIENT_DOMAIN env var).")
	flag.Parse()

	// 2. Read from environment variables and override flags if present
	if envCert := os.Getenv("CERT"); envCert != "" {
		*certFileFlag = envCert
	}
	if envKey := os.Getenv("KEY"); envKey != "" {
		*keyFileFlag = envKey
	}
	validClientDomain := *clientDomainFlag
	if envDomain := os.Getenv("VALID_CLIENT_DOMAIN"); envDomain != "" {
		validClientDomain = envDomain
	}

	// 3. Mandatory checks
	if *certFileFlag == "" || *keyFileFlag == "" {
		slog.Error("Both certificate and key paths are required.", "cert_path", *certFileFlag, "key_path", *keyFileFlag)
		fmt.Printf("Usage: %s --cert <path/to/server.crt> --key <path/to/server.key> [--valid-client-domain <domain-suffix>]\n", os.Args[0])
		return
	}

	manager := &SSLCertManager{
		certPath:          *certFileFlag,
		keyPath:           *keyFileFlag,
		validClientDomain: strings.ToLower(validClientDomain),
	}

	if manager.validClientDomain != "" {
		slog.Info("Access control is ENABLED", "required_domain_suffix", manager.validClientDomain)
	} else {
		slog.Warn("Access control is DISABLED", "reason", "valid-client-domain not set")
	}

	// Initial load and bundle
	if err := manager.LoadAndBundle(); err != nil {
		slog.Error("Initial bundling failed", "error", err)
	}

	// --- Signal Trapping and Graceful Shutdown Setup ---

	// Create a channel to listen for OS signals (SIGINT, SIGTERM)
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize shutdown channel for watcher
	manager.shutdownChan = make(chan struct{})

	// Start background watcher
	go manager.StartWatcher()

	// Start web server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		// StartServer will block until it returns an error or is shut down
		if err := manager.StartServer(); err != nil {
			serverErrors <- err
		}
	}()

	slog.Info("Service is running. Waiting for termination signal or server error.")

	// Block until a signal is received or the server errors
	select {
	case sig := <-stopChan:
		slog.Info("Received OS signal, initiating graceful shutdown", "signal", sig.String())
	case err := <-serverErrors:
		slog.Error("HTTP server failed unexpectedly, initiating shutdown", "error", err)
	}

	// Graceful Shutdown Sequence
	slog.Info("Starting shutdown sequence...")

	// 1. Stop Watcher
	close(manager.shutdownChan)

	// 2. Shut down HTTP Server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if manager.server != nil {
		if err := manager.server.Shutdown(ctx); err != nil {
			slog.Error("HTTP server forced to shutdown (timeout/error)", "error", err, "timeout", shutdownTimeout)
		} else {
			slog.Info("HTTP server gracefully stopped")
		}
	}

	slog.Info("Service successfully shut down.")
}

// getBundleFilename uses the CN from the certificate to generate a sanitized bundle filename.
func getBundleFilename(cn string) string {
	filename := strings.ReplaceAll(cn, "*", "wildcard")
	filename = strings.ReplaceAll(filename, ".", "_")
	filename = strings.ReplaceAll(filename, " ", "_")
	filename = strings.ToLower(filename)
	if filename == "" {
		filename = "certificate_bundle"
	}
	return fmt.Sprintf("%s_bundle.pem", filename)
}

// LoadAndBundle reads the cert/key, builds the chain, saves the bundle locally,
// and updates the manager's internal state.
func (m *SSLCertManager) LoadAndBundle() error {
	log := slog.Default().With("action", "bundle_load")
	log.Info("Starting Load and Bundle process")

	// Read files
	certPEM, err := os.ReadFile(m.certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file %s: %w", m.certPath, err)
	}
	keyPEM, err := os.ReadFile(m.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file %s: %w", m.keyPath, err)
	}

	// Get file modification times for tracking
	certStat, _ := os.Stat(m.certPath)
	keyStat, _ := os.Stat(m.keyPath)

	// Build the certificate chain (server cert + intermediates)
	serverCert, intermediates, err := m.buildCertChain(certPEM)
	if err != nil {
		return fmt.Errorf("failed to build cert chain: %w", err)
	}

	// 5. Save the new bundle file (includes key) and calculate expiry
	bundleFile, bundleName, minExpiry, err := m.saveBundle(serverCert, intermediates, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to save bundle: %w", err)
	}

	// Update manager state thread-safely
	m.Lock()
	defer m.Unlock()
	m.bundleName = bundleName
	m.bundleFile = bundleFile
	m.certModTime = certStat.ModTime()
	m.keyModTime = keyStat.ModTime()
	m.minExpiry = minExpiry

	log.Info("New bundle generated successfully", "bundle_name", bundleName, "min_expiry", minExpiry.Format(time.RFC3339))
	return nil
}

// buildCertChain extracts the cert and recursively fetches intermediates.
func (m *SSLCertManager) buildCertChain(certPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	log := slog.Default().With("action", "chain_build")
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM block from certificate file")
	}

	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}
	log.Info("Parsed server certificate", "subject_cn", serverCert.Subject.CommonName)

	intermediateCerts := []*x509.Certificate{}
	currentCert := serverCert

	for i := 0; i < maxChainDepth; i++ {
		if currentCert.IsCA && currentCert.CheckSignatureFrom(currentCert) == nil {
			log.Info("Chain completed: Found self-signed Root CA", "depth", i)
			break
		}

		aiaURI := extractAiaUri(currentCert)
		if aiaURI == "" {
			log.Warn("Could not find AIA URI. Chain may be incomplete. Stopping discovery.", "cert_cn", currentCert.Subject.CommonName)
			break
		}

		log.Info("Attempting to download intermediate", "aia_uri", aiaURI)

		intermediateCert, err := fetchCertificateFromURI(aiaURI)
		if err != nil {
			log.Error("Failed to fetch intermediate. Stopping discovery.", "cert_cn", currentCert.Subject.CommonName, "error", err)
			break
		}

		intermediateCerts = append(intermediateCerts, intermediateCert)
		log.Info("Successfully fetched intermediate", "subject_cn", intermediateCert.Subject.CommonName)

		currentCert = intermediateCert
	}

	return serverCert, intermediateCerts, nil
}

// extractAiaUri manually parses the AIA extension to extract the URI.
func extractAiaUri(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAuthorityInfoAccess) {
			var aia []accessDescription
			_, err := asn1.Unmarshal(ext.Value, &aia)
			if err != nil {
				return ""
			}

			for _, ad := range aia {
				if ad.Method.Equal(oidCACaIssuers) {
					// Context Specific Tag 6 (UniformResourceIdentifier)
					const uriTag = 6
					if ad.Location.Class == asn1.ClassContextSpecific && ad.Location.Tag == uriTag {
						return string(ad.Location.Bytes)
					}
				}
			}
		}
	}
	return ""
}

// fetchCertificateFromURI downloads a certificate with exponential backoff.
func fetchCertificateFromURI(uri string) (*x509.Certificate, error) {
	log := slog.Default().With("action", "fetch_cert", "uri", uri)
	client := http.Client{Timeout: 10 * time.Second}
	delay := initialDelay
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			log.Info("Retrying download", "attempt", attempt, "delay", delay)
			time.Sleep(delay)
			delay *= 2
		}

		resp, err := client.Get(uri)
		if err != nil {
			lastErr = fmt.Errorf("http request failed: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		// Try DER
		intermediateCert, err := x509.ParseCertificate(data)
		if err == nil {
			return intermediateCert, nil
		}

		// Try PEM
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "CERTIFICATE" {
			intermediateCert, err = x509.ParseCertificate(block.Bytes)
			if err == nil {
				return intermediateCert, nil
			}
		}

		lastErr = fmt.Errorf("failed to parse downloaded data (not DER or PEM)")
	}

	return nil, fmt.Errorf("failed to fetch and parse certificate from %s after %d attempts: %w", uri, maxRetries, lastErr)
}

// saveBundle writes the server cert, intermediates, and key to a single buffer/file
// and returns the bundle content and min expiry.
func (m *SSLCertManager) saveBundle(serverCert *x509.Certificate, intermediates []*x509.Certificate, keyPEM []byte) ([]byte, string, time.Time, error) {
	log := slog.Default().With("action", "save_bundle")
	bundleName := getBundleFilename(serverCert.Subject.CommonName)
	outputFile := bundleName
	var bundle bytes.Buffer

	// 1. Write the Server Cert with metadata comments
	m.writeCert(&bundle, "Server", serverCert)

	// 2. Write the Intermediates in order with metadata comments
	for i, cert := range intermediates {
		m.writeCert(&bundle, fmt.Sprintf("Intermediate %d", i+1), cert)
	}

	// 3. Write the Private Key (MANDATORY inclusion in the served bundle)
	if len(keyPEM) > 0 {
		block, _ := pem.Decode(keyPEM)
		if block != nil {
			log.Info("Writing Private Key block to bundle")

			// Add comment for Private Key
			keyComment := "\n# --- Private Key ---\n"
			if _, err := bundle.Write([]byte(keyComment)); err != nil {
				log.Warn("Failed to write key comment block", "error", err)
			}

			if err := pem.Encode(&bundle, block); err != nil {
				log.Warn("Failed to encode key block", "error", err)
			}
		} else {
			log.Warn("Failed to decode Private Key PEM block")
		}
	} else {
		log.Warn("Private key is empty. Bundle will be incomplete.")
	}

	// Calculate minimum expiry time
	minExpiry := serverCert.NotAfter
	for _, cert := range intermediates {
		if cert.NotAfter.Before(minExpiry) {
			minExpiry = cert.NotAfter
		}
	}

	// Write to disk (for external tools/debugging)
	if err := os.WriteFile(outputFile, bundle.Bytes(), 0644); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("failed to write bundle file %s: %w", outputFile, err)
	}

	log.Info("Local bundle file saved to disk", "filename", outputFile)
	return bundle.Bytes(), bundleName, minExpiry, nil
}

// writeCert is a helper to encode a certificate to PEM and write it to the buffer,
// prepending a metadata comment block for easy inspection.
func (m *SSLCertManager) writeCert(w io.Writer, certType string, cert *x509.Certificate) {
	log := slog.Default().With("action", "write_cert")
	log.Info("Writing certificate", "type", certType, "cn", cert.Subject.CommonName, "expires", cert.NotAfter.Format("2006-01-02"))

	// --- Custom Metadata Comment Block ---
	// Using RFC822 format for brevity and clarity in the comment block.
	comment := fmt.Sprintf("\n# --- %s Certificate Details ---\n", certType)
	comment += fmt.Sprintf("#   Common Name (CN): %s\n", cert.Subject.CommonName)
	comment += fmt.Sprintf("#   Issuer (Authority): %s\n", cert.Issuer.CommonName)
	comment += fmt.Sprintf("#   Valid From: %s\n", cert.NotBefore.Format(time.RFC822))
	comment += fmt.Sprintf("#   Valid To: %s\n", cert.NotAfter.Format(time.RFC822))
	comment += "# -----------------------------------\n"

	// Write the comment block to the writer
	if _, err := w.Write([]byte(comment)); err != nil {
		log.Warn("Failed to write comment block", "type", certType, "error", err)
	}
	// --- End Metadata Comment Block ---

	// Encode and write the certificate PEM block
	err := pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		log.Warn("Failed to encode/write cert", "type", certType, "error", err)
	}
}

// StartWatcher periodically checks file modification times and certificate expiry.
func (m *SSLCertManager) StartWatcher() {
	log := slog.Default().With("component", "watcher")
	ticker := time.NewTicker(watcherInterval)
	defer ticker.Stop()
	log.Info("Starting file and expiry watcher", "interval", watcherInterval)

	// Use a select statement to listen for both the ticker and the shutdown signal
	for {
		select {
		case <-m.shutdownChan:
			log.Info("Watcher received shutdown signal. Exiting.")
			return
		case <-ticker.C:
			m.CheckAndRefresh()
		}
	}
}

// CheckAndRefresh determines if a refresh is needed based on file changes or expiry.
func (m *SSLCertManager) CheckAndRefresh() {
	log := slog.Default().With("component", "watcher")
	m.RLock()
	currentMinExpiry := m.minExpiry
	currentCertModTime := m.certModTime
	currentKeyModTime := m.keyModTime
	m.RUnlock()

	// 1. Check file modification times
	certStat, errC := os.Stat(m.certPath)
	keyStat, errK := os.Stat(m.keyPath)

	if errC != nil || errK != nil {
		log.Error("Cannot stat source files", "cert_error", errC, "key_error", errK)
		return
	}

	needsRefresh := false
	if certStat.ModTime().After(currentCertModTime) {
		log.Warn("Certificate file has changed", "old_time", currentCertModTime, "new_time", certStat.ModTime())
		needsRefresh = true
	} else if keyStat.ModTime().After(currentKeyModTime) {
		log.Warn("Private key file has changed", "old_time", currentKeyModTime, "new_time", keyStat.ModTime())
		needsRefresh = true
	}

	// 2. Check certificate expiry
	refreshTime := time.Now().Add(refreshBeforeExpiry)
	if currentMinExpiry.IsZero() || currentMinExpiry.Before(refreshTime) {
		log.Warn("Certificate chain minimum expiry is nearing", "min_expiry", currentMinExpiry.Format(time.RFC3339), "refresh_window", refreshBeforeExpiry)
		needsRefresh = true
	}

	if needsRefresh {
		if err := m.LoadAndBundle(); err != nil {
			log.Error("Automated bundling failed during refresh", "error", err)
		}
	} else {
		log.Info("All checks passed. Bundle is up to date.")
	}
}

// StartServer sets up and runs the HTTP server using http.Server for graceful shutdown.
func (m *SSLCertManager) StartServer() error {
	log := slog.Default().With("component", "http_server")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssl/", m.bundleHandler)

	// Initialize the http.Server struct and store it in the manager
	m.server = &http.Server{
		Addr:    ":" + serverPort,
		Handler: mux,
	}

	log.Info("HTTP server starting", "port", serverPort, "endpoint", "/.well-known/ssl/<bundle-filename>")

	// ListenAndServe blocks until the server shuts down or an error occurs.
	if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		// Log the error if it wasn't the expected graceful shutdown signal
		log.Error("HTTP server failed to start or run", "error", err)
		return err
	}

	// Returning nil means the server was gracefully closed (http.ErrServerClosed was caught)
	return nil
}

// bundleHandler serves the current certificate bundle file after validating client access.
func (m *SSLCertManager) bundleHandler(w http.ResponseWriter, r *http.Request) {
	log := slog.Default().With("component", "http_handler", "remote_addr", r.RemoteAddr, "path", r.URL.Path)

	m.RLock()
	bundle := m.bundleFile
	bundleName := m.bundleName
	validDomain := m.validClientDomain
	m.RUnlock()

	// 1. Path check
	expectedPath := "/.well-known/ssl/" + bundleName
	if bundleName == "" || r.URL.Path != expectedPath {
		log.Warn("Request path mismatch or bundle not ready", "expected", expectedPath)
		http.NotFound(w, r)
		return
	}

	if len(bundle) == 0 {
		log.Error("Certificate bundle file is empty or not yet generated")
		http.Error(w, "Certificate bundle file is empty or not yet generated.", http.StatusServiceUnavailable)
		return
	}

	// 2. Reverse DNS Validation (if required)
	if validDomain != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		log.Info("Validating client access via reverse DNS lookup", "client_ip", host, "required_domain", validDomain)

		names, err := net.LookupAddr(host)

		isAuthorized := false
		if err == nil && len(names) > 0 {
			for _, name := range names {
				resolvedHostname := strings.TrimSuffix(strings.ToLower(name), ".")

				if strings.HasSuffix(resolvedHostname, validDomain) {
					log.Info("ACCESS GRANTED: IP resolved to matching domain", "resolved_hostname", resolvedHostname)
					isAuthorized = true
					break
				}
			}
		}

		if !isAuthorized {
			log.Warn("ACCESS DENIED: Client failed reverse DNS check", "client_ip", host, "resolved_names", names)
			http.Error(w, "Permission denied. Client domain validation failed.", http.StatusForbidden)
			return
		}
	} else {
		log.Info("Access control disabled. Serving bundle to client.")
	}

	// 3. Serve the bundle
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(bundle)
	log.Info("Successfully served certificate bundle")
}
