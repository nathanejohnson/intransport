package intransport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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

func NewInTransportClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				// This must be true or our VerifyPeerCertificate method
				// won't be called if it fails initial validation such
				// as when intermediate certificates are missing, which
				// is the whole point of this silly package.
				InsecureSkipVerify: true,

				// This is where the magic happens.
				VerifyPeerCertificate: InTransport{}.VerifyPeerCertificate,
			},
		},
	}
}

type InTransport struct {
	// Specify this method in the situation where you might otherwise have wanted to
	// install your own VerifyPeerCertificate hook into tls.Config.  If specified,
	// This method will be called after a successful InTransport verification,
	// and verifiedChains will contain appropriate data including any intermediates
	// that needed to be downloaded.
	NextVerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func (it InTransport) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
	verifiedChains, err = verifyChains(PeerCertificates)
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
func verifyChains(certs []*x509.Certificate) (chains [][]*x509.Certificate, err error) {

	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			cp.AddCert(cert)
		}
	}

	chains, err = certs[0].Verify(x509.VerifyOptions{
		Intermediates: cp,
	})

	if err != nil {
		var dledIntermediates []*x509.Certificate

		dledIntermediates, err = buildChain(certs[len(certs)-1])
		if err != nil {
			return nil, fmt.Errorf("failed to find chain: %s", err)
		}
		for _, cert := range dledIntermediates {
			cp.AddCert(cert)
		}
		chains, err = certs[0].Verify(x509.VerifyOptions{
			Intermediates: cp,
		})
		if err != nil {
			return nil, fmt.Errorf("chain failed verification after fetch: %s", err)
		}
	}
	return
}

func buildChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	tmpCert := cert
	var retval []*x509.Certificate
	for {
		_, err := tmpCert.Verify(x509.VerifyOptions{})
		if err == nil {
			break
		}

		tmpCert, err = fetchIssuingCert(tmpCert)

		if err != nil {
			return nil, err
		}
		retval = append(retval, tmpCert)
	}
	return retval, nil
}

func fetchIssuingCert(cert *x509.Certificate) (*x509.Certificate, error) {
	// this attempts to do two things:
	// 1) avoid stampede problem - minimizes fetches of a cert on cache miss
	// 2) avoid long locks on the outer map.
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("failed to fetchintermediates for %s",
			cert.Subject.CommonName)
	}
	mapKey := cert.Issuer.CommonName + ":" + cert.Issuer.SerialNumber
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
	defer cce.Unlock()

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
