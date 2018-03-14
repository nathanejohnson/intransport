package intransport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

type certCacheEntry struct {
	sync.RWMutex
	cert *x509.Certificate
}
type certCache struct {
	sync.Mutex
	m map[string]*certCacheEntry
	c *http.Client
}

var (
	// MustStapleValue is the value in the MustStaple extension.
	MustStapleValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

	//MustStapleOID is the OID of the must staple
	MustStapleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	cc = &certCache{
		m: make(map[string]*certCacheEntry),
		c: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 0,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   3 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
)

// PeerCertVerifier - this is a method type that is plugged into a tls.Config.VerifyPeerCertificate,
// or into our NextVerifyPeerCertificate.
type PeerCertVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// NewInTransportHTTPClient - generate an http client with sensible defaults.
// Optionally pass a *tls.Config that will be used as a basis for tls configuration.
func NewInTransportHTTPClient(tlsc *tls.Config) *http.Client {
	return &http.Client{
		Transport: NewInTransport(tlsc),
	}
}

// NewInTransport - create a new http transport suitable for client connections.
// InTransport implements http.RoundTripper, and can be used like so:
//
//    it := intransport.NewInTranport(nil)
//    c := &http.Client{
//        Transport: it,
//    }
func NewInTransport(tlsc *tls.Config) *InTransport {
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
	}

	it := &InTransport{
		Transport: t,
	}

	if tlsc != nil {
		it.TLS = tlsc.Clone()
	} else {
		it.TLS = new(tls.Config)
	}
	it.TLS.VerifyPeerCertificate = it.VerifyPeerCertificate
	it.TLS.InsecureSkipVerify = true
	t.TLSClientConfig = it.TLS

	return it
}

// InTransport - this implements an http.RoundTripper and handles the fetching
// of missing intermediate certificates, and (soon) verifying OCSP stapling
// in the event there is a "must staple" set on the certificate.
type InTransport struct {
	// Specify this method in the situation where you might otherwise have wanted to
	// install your own VerifyPeerCertificate hook into tls.Config.  If specified,
	// This method will be called after a successful InTransport verification,
	// and verifiedChains will contain appropriate data including any intermediates
	// that needed to be downloaded.
	NextVerifyPeerCertificate PeerCertVerifier

	TLS                 *tls.Config
	TLSHandshakeTimeout time.Duration

	Transport http.RoundTripper
}

// RoundTrip - this implements the http.RoundTripper interface, and makes it suitable
// for use as a transport.
func (it *InTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := it.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Now verify hostname on TLS since we couldn't see it in our
	// VerifyPeerCertificate callback.
	if resp.TLS != nil {

		err := validateHost(resp.TLS.PeerCertificates, resp.Request.Host)
		if err == nil {
			err = it.validateOCSP(resp.TLS)
		}

		if err != nil {
			_ = resp.Body.Close()
			return nil, err
		}

	} else if req.URL.Scheme == "https" {
		err := fmt.Errorf("https requested, but tls is nil\n")
		_ = resp.Body.Close()
		return nil, err
	}

	return resp, nil

}

func validateHost(certs []*x509.Certificate, host string) error {
	crt := certs[0]

	if hasPort(host) {
		host = host[:strings.LastIndex(host, ":")]
	}

	err := crt.VerifyHostname(host)
	if err != nil {
		return err
	}

	return nil

}

func (it *InTransport) validateOCSP(connState *tls.ConnectionState) error {
	peers := connState.PeerCertificates
	if len(peers) == 0 {
		return fmt.Errorf("no peer certificates presented")
	}
	crt := peers[0]

	mustStaple := false
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(MustStapleOID) {
			if bytes.Equal(ext.Value, MustStapleValue) {
				mustStaple = true
			}
			break
		}
	}

	validatedStaple := false

	if connState.OCSPResponse != nil {

		// Validate the staple if present
		// Let's grab the chain

		chains, err := it.verifyChains(peers)
		if err != nil {
			return err
		}

		var chain []*x509.Certificate
		if len(chains) < 1 {
			err = fmt.Errorf("invalid chains length")
		} else {
			chain = chains[0]
			if len(chain) < 2 {
				err = fmt.Errorf("invalid chain length")
			}
		}
		if err != nil {
			return err
		}

		ocspResp, err := ocsp.ParseResponseForCert(connState.OCSPResponse, crt, chain[1])
		if err != nil {
			return err
		}
		if ocspResp.Status != ocsp.Good {

			return fmt.Errorf("invalid ocsp validation: %s", ocsp.ResponseStatus(ocspResp.Status).String())
		}
		validatedStaple = true
	}

	if mustStaple && !validatedStaple {
		return fmt.Errorf("certificate was marked with OCSP must-staple and no staple could be verified")
	}
	return nil
}

// lifted from standard library net/http/http.go
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

// VerifyPeerCertificate - this is the method that is to be plugged into
// tls.Config VerifyPeerCertificate.  If using this method inside of a custom
// built htttp.Transport, you must also set InsecureSkipVerify to true.  When
// set to false, a certificate that isn't trusted to the root and has missing
// intermediate certs will prevent VerifyPeerCertificate from being called.
// This method will still ensure that a valid chain exists from the presented
// certificates(s) to a trusted root certificate.  The difference between this
// and the default TLS verification is that missing intermediates will be
// fetched until either a valid path to a trusted root is found or no further
// intermediates can be found.  If a chain cannot be established, the
// connection will fail .  If a chain can be established, then the optional
// NextVerifyPeerCertificate() method will be called, if specified.  If this
// method returns an error, it will stop the connection.
func (it *InTransport) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates supplied")
	}

	PeerCertificates := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		PeerCertificates = append(PeerCertificates, cert)
	}

	var err error
	var verifiedChains [][]*x509.Certificate
	verifiedChains, err = it.verifyChains(PeerCertificates)
	if err != nil {
		return err
	}
	if it.NextVerifyPeerCertificate != nil {
		err = it.NextVerifyPeerCertificate(rawCerts, verifiedChains)
	}

	return err
}

// verifyChains - this takes cert(s) and does it's best to find a path to a recognized root,
// fetching intermediate certs that may be missing.
func (it *InTransport) verifyChains(certs []*x509.Certificate) (chains [][]*x509.Certificate, err error) {
	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			cp.AddCert(cert)
		}
	}

	chains, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         it.TLS.RootCAs,
		Intermediates: cp,
	})

	if err != nil {
		var dledIntermediates []*x509.Certificate

		dledIntermediates, err = it.buildChain(certs[len(certs)-1])
		if err != nil {
			return nil, fmt.Errorf("failed to find chain: %s", err)
		}
		for _, cert := range dledIntermediates {
			cp.AddCert(cert)
		}
		chains, err = certs[0].Verify(x509.VerifyOptions{
			Roots:         it.TLS.RootCAs,
			Intermediates: cp,
		})
		if err != nil {
			return nil, fmt.Errorf("chain failed verification after fetch: %s", err)
		}
	}
	return
}

func (it *InTransport) buildChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	tmpCert := cert
	var retval []*x509.Certificate
	var lastError error
	for {
		// TODO - set a limit to how many iterations of this loop
		// what's sane?
		_, lastError = tmpCert.Verify(x509.VerifyOptions{
			Roots: it.TLS.RootCAs,
			// We don't care about dns names here
		})
		if lastError == nil {
			break
		}
		var err error
		tmpCert, err = fetchIssuingCert(tmpCert)

		if err != nil {
			return nil, err
		}
		retval = append(retval, tmpCert)
	}
	if lastError != nil {
		return nil, lastError
	}
	return retval, nil
}

func fetchIssuingCert(cert *x509.Certificate) (*x509.Certificate, error) {
	// this attempts to do two things:
	// 1) avoid stampede problem - minimizes fetches of a cert on cache miss
	// 2) avoid long locks on the outer map.
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("failed to fetch intermediates for %s",
			cert.Subject.CommonName)
	}

	var mapKey string
	if len(cert.AuthorityKeyId) > 0 {
		enc := base64.RawStdEncoding.EncodeToString(cert.AuthorityKeyId)
		mapKey = cert.Issuer.CommonName + ":" + enc
	} else {
		mapKey = cert.Issuer.CommonName
	}
	cc.Lock()
	cce, ok := cc.m[mapKey]
	if ok {
		cc.Unlock()
		cce.Lock()
		crt := cce.cert

		if crt != nil {
			cce.Unlock()
			return crt, nil
		}
	} else {
		cce = new(certCacheEntry)
		cce.Lock()
		cc.m[mapKey] = cce
		cc.Unlock()

	}

	// Once we're here, cce is locked, cc is unlocked
	// defer is nowhere near as slow as the code below
	defer func() {
		cce.Unlock()
	}()

	// I've yet to see more than one IssuingCertificateURL,
	// but just in case...
	var err error
	var fetchedCert *x509.Certificate
	for _, url := range cert.IssuingCertificateURL {
		var resp *http.Response
		resp, err = cc.c.Get(url)
		if err != nil {
			continue
		}

		var raw []byte
		raw, err = ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		fetchedCert, err = x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		cce.cert = fetchedCert
		break
	}
	if err != nil {
		return nil, err
	}
	return fetchedCert, nil
}
