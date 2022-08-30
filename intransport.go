package intransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// StatusRequestExtension - status_request
const StatusRequestExtension = 5

var (
	// ErrNoPeerCerts - this is returned when there are no peer certs presented.
	ErrNoPeerCerts = errors.New("no peer certificates presented")

	// ErrInvalidChainLength - this is returned when the chain length is less than 2 for a "chains" entry,
	// IOW there must be at leat one peer cert in addition to the leaf.
	ErrInvalidChainLength = errors.New("invalid chain length")

	// ErrInvalidChainsLength - this is returned when the chains length is less than 1
	ErrInvalidChainsLength = errors.New("invalid chains length")

	// ErrOCSPNotStapled - this is returned when the OCSP Must Staple extension is present but a valid
	// OCSP staple was not found.
	ErrOCSPNotStapled = errors.New("certificate was marked with OCSP must-staple and no staple could be verified")

	// ErrNoCertificates - this is returned in the unlikely event that no
	// peer certificates are provided whatsoever.  This should never be
	// seen.
	ErrNoCertificates = errors.New("no certificates supplied")

	// MustStapleValue is the value in the MustStaple extension.
	// DER encoding of []int{5}.
	// https://tools.ietf.org/html/rfc6066#section-1.1
	MustStapleValue, _ = asn1.Marshal([]int{StatusRequestExtension})

	// MustStapleOID is the OID of the must staple.
	// Must staple oid is id-pe-tlsfeature  as defined here
	// https://tools.ietf.org/html/rfc7633#section-6
	MustStapleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
)

// peerCertViewer - this is a method type that is plugged into a tls.Config.VerifyPeerCertificate,
// or into our NextVerifyPeerCertificate.
type peerCertViewer func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

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
//	it := intransport.NewInTranport(nil)
//	c := &http.Client{
//	    Transport: it,
//	}
func NewInTransport(tlsc *tls.Config) *InTransport {
	return NewInTransportFromTransport(nil, nil, tlsc)
}

// NewInTransportFromTransport - use t, dialer and tlsc as templates.  Any can be nil and sane defaults
// will be used.  If tlsc.VerifyPeerCertificate is specified, it will be called with the same semantics
// as before, but after we fetch intermediates and validate chains (if necessary).  Similarly, if
// tlsc.VerifyConnection is specified, it will be called with the same semantics as before,
// but after we validate stapled ocsp.
func NewInTransportFromTransport(t *http.Transport, dialer *net.Dialer, tlsc *tls.Config) *InTransport {
	return NewInTransportFromTransportWithCache(t, dialer, tlsc, nil)
}

// NewInTransportFromTransportWithCache - Same as NewInTransportFromTransport, with the option of specifying
// a cache implementation for fetched intermediates.  If nil, the default cacher will use the map cache implementation.
func NewInTransportFromTransportWithCache(t *http.Transport, dialer *net.Dialer, tlsc *tls.Config, cache Cacher) *InTransport {
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}
	if t == nil {
		t = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		t = t.Clone()
		if t.DialContext == nil {
			t.DialContext = dialer.DialContext
		}
	}
	if tlsc == nil {
		tlsc = new(tls.Config)
	} else {
		tlsc = tlsc.Clone()
	}
	if cache == nil {
		cache = NewMapCache()
	}
	it := &InTransport{
		t:                         t,
		NextVerifyPeerCertificate: tlsc.VerifyPeerCertificate,
		NextVerifyConnection:      tlsc.VerifyConnection,
		dialer:                    dialer,
		IntermediateHTTPClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 0,
				}).DialContext,

				// Since we cache responses, all http activity should be
				// one-and-done.
				DisableKeepAlives: true,

				// This shouldn't be needed, since I don't believe
				// the server url locations are ever tlsc enabled?
				TLSHandshakeTimeout: 3 * time.Second,

				// This also shouldn't be needed, but doesn't hurt anything
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		cache: cache,
	}

	it.tlsc = tlsc
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		conf := it.tlsc.Clone()
		// Must configure InsecureSkipVerify to ensure that VerifyPeerCertificate
		// is always called, which allows us to fetch missing intermediates.
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return it.verifyPeerCertificate(h, rawCerts, verifiedChains)
		}

		// As of go 1.15, we can now validate OCSP during handshake.
		conf.VerifyConnection = func(state tls.ConnectionState) error {
			err := it.validateOCSP(h, &state)
			if err != nil {
				return err
			}
			if it.NextVerifyConnection != nil {
				return it.NextVerifyConnection(state)
			}
			return nil
		}

		d := tls.Dialer{
			NetDialer: it.dialer,
			Config:    conf,
		}
		return d.DialContext(ctx, network, addr)
	}
	return it

}

// InTransport - this implements an http.RoundTripper and handles the fetching
// of missing intermediate certificates, and verifying OCSP stapling, and
// in the event there is a "must staple" set on the certificate it will fail on
// missing staple.
type InTransport struct {
	// Specify this method in the situation where you might otherwise have wanted to
	// install your own VerifyPeerCertificate hook into tls.Config.  If specified,
	// This method will be called after a successful InTransport verification,
	// and verifiedChains will contain appropriate data including any intermediates
	// that needed to be downloaded.  This is also set when a VerifyPeerCertificate
	// method is present on the passed tls.Config to one of the New methods above.
	NextVerifyPeerCertificate peerCertViewer

	// NextVerifyConnection is similar to NextVerityPeerCertificate, but for the VerifyConnection instead.
	// Similarly to above, this is automatically set if VerifyConnection is set on
	// tls.Config passed to any of the New methods above.
	NextVerifyConnection func(cs tls.ConnectionState) error

	// IntermediateHTTPClient is an http client used for fetching intermediate certs
	// that are missing.  The default created with the New* methods is probably
	// sane for almost all use cases, but exporting this just in case.  If
	// you need to set this, do it before you start using InTransport as an
	// http.Roundtripper.
	IntermediateHTTPClient *http.Client

	t      *http.Transport
	tlsc   *tls.Config
	dialer *net.Dialer
	cache  Cacher
}

// RoundTrip - implement http.RoundTripper interface
func (it *InTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return it.t.RoundTrip(req)
}

func (it *InTransport) validateOCSP(serverName string, connState *tls.ConnectionState) error {
	peers := connState.PeerCertificates
	if len(peers) == 0 {
		return ErrNoPeerCerts
	}
	crt := peers[0]

	mustStaple := false
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(MustStapleOID) {
			if bytes.Equal(ext.Value, MustStapleValue) {
				mustStaple = true
			} else {
				// technically the value is a DER encoded SEQUENCE OF INTEGER,
				// so see if there is more than one integer specified.  doubt
				// this will be seen in the wild, currently there is only one
				// defined value per RFC.  but hey, due diligence.  all that.
				var tlsExts []int
				_, err := asn1.Unmarshal(ext.Value, &tlsExts)
				if err != nil {
					return fmt.Errorf("malformed must staple extension: %w", err)
				}
				for _, tlsExt := range tlsExts {
					if tlsExt == StatusRequestExtension {
						mustStaple = true
						break
					}
				}
			}
			break
		}
	}

	validatedStaple := false

	if connState.OCSPResponse != nil {

		// Validate the staple if present
		// Let's grab the chain
		chains, err := it.verifyChains(serverName, connState.PeerCertificates)
		if err != nil {
			return err
		}

		var chain []*x509.Certificate
		if len(chains) < 1 {
			err = ErrInvalidChainsLength
		} else {
			chain = chains[0]
			if len(chain) < 2 {
				err = ErrInvalidChainLength
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

		if ocspResp.NextUpdate.After(time.Now()) {
			// for now, don't fail on an expired staple unless must staple is specified.
			// maybe revisit this
			validatedStaple = true
		}

	}

	if mustStaple && !validatedStaple {
		return ErrOCSPNotStapled
	}
	return nil
}

// verifyPeerCertificate - The difference between this
// and the default tlsc verification is that missing intermediates will be
// fetched until either a valid path to a trusted root is found or no further
// intermediates can be found.  If a chain cannot be established, the
// connection will fail .  If a chain can be established, then the optional
// NextVerifyPeerCertificate() method will be called, if specified.  If this
// method returns an error, it will stop the connection.
func (it *InTransport) verifyPeerCertificate(serverName string, rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return ErrNoCertificates
	}

	PeerCertificates := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("intransport: error parsing certificate: %w", err)
		}
		PeerCertificates = append(PeerCertificates, cert)
	}

	var err error
	var verifiedChains [][]*x509.Certificate
	verifiedChains, err = it.verifyChains(serverName, PeerCertificates)
	if err != nil {
		return fmt.Errorf("intransport: validation error: %w", err)
	}
	if it.NextVerifyPeerCertificate != nil {
		err = it.NextVerifyPeerCertificate(rawCerts, verifiedChains)
		if err != nil {
			err = fmt.Errorf("intransport: NextVerifyPeerCertificate() failed: %w", err)
		}
	}

	return err
}

// verifyChains - this takes cert(s) and does its best to find a path to a recognized root,
// fetching intermediate certs that may be missing.
func (it *InTransport) verifyChains(serverName string, certs []*x509.Certificate) (chains [][]*x509.Certificate, err error) {
	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			cp.AddCert(cert)
		}
	}

	// Validate hostname first, because chains are comparatively expensive.  Also the Verify
	// below won't fail on an empty serverName unless we explicitly check it here.
	if err := certs[0].VerifyHostname(serverName); err != nil {
		return nil, err
	}

	// Now check the chains.
	chains, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         it.tlsc.RootCAs,
		Intermediates: cp,
		DNSName:       serverName,
	})

	if err != nil {
		// This will be a chain failure.  Try to fetch intermediates now.
		var fetched []*x509.Certificate

		fetched, err = it.buildMissingChain(certs[len(certs)-1])
		if err != nil {
			return nil, fmt.Errorf("failed to find chain: %w", err)
		}
		for _, cert := range fetched {
			cp.AddCert(cert)
		}
		chains, err = certs[0].Verify(x509.VerifyOptions{
			Roots:         it.tlsc.RootCAs,
			Intermediates: cp,
			DNSName:       serverName,
		})
		if err != nil {
			return nil, fmt.Errorf("chain failed verification after fetch: %w", err)
		}
	}
	return
}

// This attempts to build the missing links of the chain, and returns any intermediates it may have fetched.
func (it *InTransport) buildMissingChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	tmpCert := cert
	var retval []*x509.Certificate
	var lastError error
	for i := 0; i < 5; i++ {
		_, lastError = tmpCert.Verify(x509.VerifyOptions{
			Roots: it.tlsc.RootCAs,
			// We don't care about dns names here
		})
		if lastError == nil {
			break
		}
		var err error
		tmpCert, err = it.fetchIssuingCert(tmpCert)

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

// This grabs the issuing cert from the issuing certificate extension.
func (it *InTransport) fetchIssuingCert(cert *x509.Certificate) (*x509.Certificate, error) {
	// this attempts to do two things:
	// 1) avoid stampede problem - minimizes fetches of a cert on cache miss
	// 2) avoid long locks on the outer map.
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("cert has empty IssuingCertificateURL: %s",
			cert.Subject.CommonName)
	}

	var mapKey string
	if len(cert.AuthorityKeyId) > 0 {
		enc := base64.RawStdEncoding.EncodeToString(cert.AuthorityKeyId)
		mapKey = cert.Issuer.CommonName + ":" + enc
	} else {
		mapKey = cert.Issuer.CommonName
	}
	cce := it.cache.LockedCachedCert(mapKey)
	var crt *x509.Certificate
	if crt = cce.Cert(); crt != nil && crt.NotAfter.After(time.Now()) {
		cce.Unlock()
		return crt, nil
	}

	defer cce.Unlock()

	// I've yet to see more than one IssuingCertificateURL,
	// but just in case...
	var err error
	var fetchedCert *x509.Certificate
	for _, urlString := range cert.IssuingCertificateURL {
		var resp *http.Response
		resp, err = it.IntermediateHTTPClient.Get(urlString)
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
		cce.SetCert(fetchedCert)
		break
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuing certificate: %w", err)
	}
	return fetchedCert, nil
}
