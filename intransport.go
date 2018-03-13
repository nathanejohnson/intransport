package intransport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
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

var cc = &certCache{
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

type dialSession struct {
	it  *InTransport
	chi *tls.ClientHelloInfo
}

// PeerCertVerifier - this is a method type that is plugged into a tls.Config.VerifyPeerCertificate,
// or into our NextVerifyPeerCertificate.
type PeerCertVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// NewInTransportClient - generate an http client with sensible deaults
// that will fetch missing intermediate certificates as needed.
func NewInTransportHTTPClient(tlsc *tls.Config) (*InTransport, *http.Client) {
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

	return it, &http.Client{
		Transport: it,
	}
}

type DNSFutzer func(DNSName string) string

type InTransport struct {
	// Specify this method in the situation where you might otherwise have wanted to
	// install your own VerifyPeerCertificate hook into tls.Config.  If specified,
	// This method will be called after a successful InTransport verification,
	// and verifiedChains will contain appropriate data including any intermediates
	// that needed to be downloaded.
	NextVerifyPeerCertificate PeerCertVerifier

	// This is a hook you can like an /etc/hosts lookup, but in code.
	// Used internally for testing, but might be generally useful.
	DNSFutzer DNSFutzer

	TLS                 *tls.Config
	TLSHandshakeTimeout time.Duration

	Transport http.RoundTripper
}

func (it *InTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := it.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Now verify hostname on TLS since we couldn't see it in our
	// VerifyPeerCertificate callback.
	if resp.TLS != nil {
		if len(resp.TLS.PeerCertificates) == 0 {
			_, _ = io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("no peer certificates presented")
		}
		h := resp.Request.Host

		if hasPort(h) {
			h = h[:strings.LastIndex(h, ":")]
		}

		err = resp.TLS.PeerCertificates[0].VerifyHostname(h)
		if err != nil {
			return nil, err
		}

	}
	return resp, err
}

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
		cert := cce.cert

		if cert != nil {
			cce.Unlock()
			return cert, nil
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
