package intransport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type intMeta struct {
	server      *httptest.Server
	cert        *x509.Certificate
	privKey     *rsa.PrivateKey
	caIssuerURL string
}

func (im *intMeta) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	buf := bytes.NewReader(im.cert.Raw)
	_, _ = io.Copy(w, buf)
}

var (
	hostCNs         []string
	intermediateCNs []string

	hostServers         = make(map[string]*httptest.Server)
	intermediateServers = make(map[string]*intMeta)
	serial              = int64(9000)
	rootPool            = x509.NewCertPool()
	writeFiles          bool
	logChains           bool
)

func prepDirs(intDir, hostDir string) error {

	err := os.RemoveAll(intDir)
	if err != nil {
		return err
	}
	err = os.RemoveAll(hostDir)
	if err != nil {
		return err
	}

	err = os.Mkdir(intDir, 0755)
	if err != nil {
		return err
	}

	return os.Mkdir(hostDir, 0755)
}

func readHosts(iFile, hFile string) error {
	ifh, err := os.Open(iFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = ifh.Close()
	}()
	hfh, err := os.Open(hFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = hfh.Close()
	}()

	iScanner := bufio.NewScanner(ifh)
	for iScanner.Scan() {

		s := iScanner.Text()
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		intermediateCNs = append(intermediateCNs, s)
	}
	if iScanner.Err() != nil {
		return err
	}
	hScanner := bufio.NewScanner(hfh)
	for hScanner.Scan() {
		s := hScanner.Text()
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		hostCNs = append(hostCNs, s)
	}
	return nil
}

func TestMain(m *testing.M) {
	var err error
	ev := 1
	defer func() {

		for _, hs := range hostServers {
			hs.Close()
		}
		for _, is := range intermediateServers {
			is.server.Close()
		}
		// This defer will probably on get called if err is non-nil,
		// but doesn't hurt to check.
		if err != nil {
			fmt.Printf("Fatal error in TestMain: %s", err)
		}
		os.Exit(ev)

	}()
	wftxt := os.Getenv("WRITE_FILES")
	if wftxt != "" {
		writeFiles, _ = strconv.ParseBool(wftxt)
	}

	lctxt := os.Getenv("LOG_CHAINS")
	if lctxt != "" {
		logChains, _ = strconv.ParseBool(lctxt)
	}

	basePath := "_testdata"
	intDir := filepath.Join(basePath, "intermediates")
	hostDir := filepath.Join(basePath, "hosts")
	hostFile := filepath.Join(basePath, "insecurities.txt")
	intFile := filepath.Join(basePath, "intermediates.txt")

	err = readHosts(intFile, hostFile)
	if err != nil {
		return
	}
	if writeFiles {
		err = prepDirs(intDir, hostDir)
		if err != nil {
			return
		}
	}

	var rootPriv *rsa.PrivateKey
	rootPriv, err = genKeyAndMaybeWrite(filepath.Join(basePath, "rootCA.key"))
	if err != nil {
		return
	}

	var csr *x509.CertificateRequest
	csr, err = makeCSR("Mister Sunshine's Root CA", rootPriv, false)
	if err != nil {
		return
	}
	var rootCert *x509.Certificate

	rootCert, err = signCSR(csr, rootPriv, nil, "", true, false)
	if err != nil {
		return
	}

	if writeFiles {
		err = writeCert(filepath.Join(basePath, "rootCA.pem"), rootCert.Raw)
		if err != nil {
			return
		}
	}

	rootPool.AddCert(rootCert)
	rootIntM := &intMeta{
		cert:    rootCert,
		privKey: rootPriv,
	}

	rootS := httptest.NewServer(rootIntM)
	rootIntM.caIssuerURL = rootS.URL + "/root.crt"

	steps := len(hostCNs) / len(intermediateCNs)
	for i, icn := range intermediateCNs {
		fileName := icn + ".key"
		var priv *rsa.PrivateKey
		priv, err = genKeyAndMaybeWrite(filepath.Join(intDir, fileName))
		if err != nil {
			return
		}

		var csr *x509.CertificateRequest
		csr, err = makeCSR(fmt.Sprintf("%s intermediate CA", icn), priv, false)
		if err != nil {
			return
		}
		var intCrt *x509.Certificate

		intCrt, err = signCSR(csr, rootPriv, rootCert, rootIntM.caIssuerURL, true, false)

		if err != nil {
			return
		}

		certFileName := icn + ".crt"
		if writeFiles {
			err = writeCert(filepath.Join(intDir, certFileName), intCrt.Raw)
			if err != nil {
				return
			}
		}

		inm := &intMeta{
			cert:    intCrt,
			privKey: priv,
		}
		s := httptest.NewServer(inm)

		inm.caIssuerURL = fmt.Sprintf("%s/%s.crt", s.URL, icn)
		inm.server = s
		if err != nil {
			return
		}

		intermediateServers[icn] = inm

		beg := i * steps
		end := beg + steps
		for j := beg; j < end; j++ {
			hcn := hostCNs[j]
			fileName = hcn + ".key"
			certFileName = hcn + ".crt"
			priv, err = genKeyAndMaybeWrite(filepath.Join(hostDir, fileName))
			if err != nil {
				return
			}
			csr, err = makeCSR(hcn, priv, true)
			if err != nil {
				return
			}
			var crt *x509.Certificate
			crt, err = signCSR(csr, inm.privKey, inm.cert, inm.caIssuerURL, false, j%2 == 0)
			if err != nil {
				return
			}
			if writeFiles {
				err = writeCert(filepath.Join(hostDir, certFileName), crt.Raw)

				if err != nil {
					return
				}
			}
			s = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintln(w, "hi there")
			}))
			var ocspResp []byte
			tmpl := ocsp.Response{
				Status:       ocsp.Good,
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().Add(time.Hour),
				SerialNumber: crt.SerialNumber,
			}
			ocspResp, err = ocsp.CreateResponse(inm.cert, crt, tmpl, inm.privKey)
			if err != nil {
				return
			}
			tlsc := &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{crt.Raw},
						PrivateKey:  priv,
						OCSPStaple:  ocspResp,
					},
				},
			}

			tlsc.BuildNameToCertificate()
			s.TLS = tlsc
			s.StartTLS()
			hostServers[hcn] = s
		}
	}

	ev = m.Run()
}

// This tests functionality, and also beats up on the cache a bit.
func TestMissingIntermediates(t *testing.T) {

	wg := &sync.WaitGroup{}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
	}
	d := &net.Dialer{
		Timeout:   time.Second * 5,
		KeepAlive: 0,
	}
	tlsc := &tls.Config{
		RootCAs: rootPool,
	}
	if logChains {
		tlsc.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for i, chain := range verifiedChains {
				for j, cert := range chain {
					t.Logf("chain %d cert %d: CN: %s Issuer CN : %s",
						i,
						j,
						cert.Subject.CommonName, cert.Issuer.CommonName,
					)
				}
			}
			return nil
		}
	}
	trans := NewInTransportFromTransport(tr, d, tlsc)

	c := &http.Client{Transport: trans}

	for hname, s := range hostServers {
		surl, _ := url.Parse(s.URL)
		port := surl.Port()
		surl.Host = fmt.Sprintf("%s:%s", hname, port)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			serverURL := surl.String()
			go t.Run(fmt.Sprintf("%s-%d", hname, i), func(t *testing.T) {
				defer func() {
					wg.Done()
				}()
				resp, err := c.Get(serverURL)
				if err != nil {
					t.Errorf("got error fetching %s: %s", serverURL, err)
					t.Fail()
					return
				}
				_, err = ioutil.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Errorf("got error reading from response: %s", err)
					t.Fail()
					return
				}
			})
		}
	}
	wg.Wait()

}

func TestHostNameValidation(t *testing.T) {
	hName1 := hostCNs[0]
	hName2 := hostCNs[1]
	tServer1 := hostServers[hName1]
	tServer2 := hostServers[hName2]
	goodURL, _ := url.Parse(tServer1.URL)
	_, p, _ := net.SplitHostPort(goodURL.Host)
	goodURL.Host = fmt.Sprintf("%s:%s", hName1, p)
	badURL, _ := url.Parse(tServer2.URL)
	_, p, _ = net.SplitHostPort(badURL.Host)
	badURL.Host = fmt.Sprintf("%s:%s", hName1, p)

	trans := NewInTransport(&tls.Config{RootCAs: rootPool})
	c := &http.Client{Transport: trans}
	resp, err := c.Get(goodURL.String())

	if err != nil {
		t.Errorf("unexpected error on good url: %s", err)
		t.Fail()
		return
	}

	_, _ = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()

	resp, err = c.Get(badURL.String())
	if err == nil {
		t.Errorf("badURL succeeded, should have failed")
		t.Fail()
		_, _ = ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
	} else {
		t.Logf("expected failure for badURL: %s", err)
		var hErr x509.HostnameError
		if !errors.As(err, &hErr) {
			t.Log("error was not HostNameError")
			t.Fail()
		}
	}

}

func TestExpectedOCSPFailures(t *testing.T) {
	testbed := hostServers[hostCNs[0]]
	// Save staple for future use
	origStaple := testbed.TLS.Certificates[0].OCSPStaple
	testcrt, err := x509.ParseCertificate(testbed.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Errorf("failed parsing certificate: %s", err)
		t.FailNow()
	}

	issuer := intermediateServers[intermediateCNs[0]]
	tr := &http.Transport{
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
	}
	d := &net.Dialer{
		Timeout:   time.Second * 5,
		KeepAlive: 0,
	}
	tlsc := &tls.Config{
		RootCAs: rootPool,
	}
	if logChains {
		tlsc.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for i, chain := range verifiedChains {
				for j, cert := range chain {
					t.Logf("chain %d cert %d: CN: %s Issuer CN : %s",
						i,
						j,
						cert.Subject.CommonName, cert.Issuer.CommonName,
					)
				}
			}
			return nil
		}
	}
	trans := NewInTransportFromTransport(tr, d, tlsc)
	// Force connection to re-establish after every test.
	c := &http.Client{Transport: trans}

	type failFunc func(resp *ocsp.Response) (outResp []byte, expectSuccess bool)

	testTable := map[string]failFunc{
		"Canary OCSP": func(resp *ocsp.Response) ([]byte, bool) {
			// test the test
			rawResp, err := ocsp.CreateResponse(issuer.cert, testcrt, *resp, issuer.privKey)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				t.FailNow()
			}
			return rawResp, true
		},
		"Bad OCSP Serial": func(resp *ocsp.Response) ([]byte, bool) {
			resp.SerialNumber = NextSerial()
			rawResp, err := ocsp.CreateResponse(issuer.cert, testcrt, *resp, issuer.privKey)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				t.FailNow()
			}

			return rawResp, false
		},
		"Expired OCSP": func(resp *ocsp.Response) ([]byte, bool) {
			resp.NextUpdate = time.Now().Add(-time.Hour)
			rawResp, err := ocsp.CreateResponse(issuer.cert, testcrt, *resp, issuer.privKey)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				t.FailNow()
			}

			return rawResp, false
		},
		"Bad Chain OCSP cert": func(resp *ocsp.Response) ([]byte, bool) {
			// grab a cert from another issuer.  we know that the first host
			// was signed with the first intermediate, so let's grab another one
			// and make an otherwise valid-looking OCSP response from the wrong
			// issuer.

			badIssuer := intermediateServers[intermediateCNs[3]]
			crt := badIssuer.cert

			rawResp, err := ocsp.CreateResponse(crt, testcrt, *resp, badIssuer.privKey)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				t.FailNow()
			}

			return rawResp, false
		},
		"OCSP Must Staple Missing Staple": func(resp *ocsp.Response) ([]byte, bool) {
			return nil, false
		},
	}
	surl, _ := url.Parse(testbed.URL)
	port := surl.Port()
	surl.Host = fmt.Sprintf("%s:%s", hostCNs[0], port)

	for desc, tfunc := range testTable {
		t.Run(desc, func(t *testing.T) {
			respVal, err := ocsp.ParseResponse(origStaple, issuer.cert)
			if err != nil {
				t.Errorf("Unexpected failure parsing ocsp response: %s", err)
				t.FailNow()
			}
			resp, expectSuccess := tfunc(respVal)
			testbed.TLS.Certificates[0].OCSPStaple = resp
			httpresp, err := c.Get(surl.String())
			if err == nil {
				if !expectSuccess {
					t.Errorf("subtest %s: unexpected success", desc)
					t.Fail()
				} else {
					t.Logf("subtest %s: nil error returned, as expected", desc)
				}
			} else {
				if expectSuccess {
					t.Errorf("subtest %s: unexpected failure: %s", desc, err)
					t.Fail()
				} else {
					t.Logf("subtest %s: expected failure: %s", desc, err)
				}
			}
			if httpresp != nil {
				_, err = io.Copy(ioutil.Discard, httpresp.Body)
				if err != nil {
					t.Errorf("error disposing of the body: %s", err)
					t.Fail()
				}
				err = httpresp.Body.Close()
				if err != nil {
					t.Fail()
					t.Errorf("error closing the body: %s", err)
				}
			}
		})
	}
	testbed.TLS.Certificates[0].OCSPStaple = origStaple
}

func makeCSR(cname string, priv *rsa.PrivateKey, addSAN bool) (request *x509.CertificateRequest, err error) {
	req := &x509.CertificateRequest{
		Version: 0,
		Subject: pkix.Name{
			Organization:       []string{"Mister Sunshine's fun shop"},
			OrganizationalUnit: []string{"R&D"},
			Country:            []string{"US"},
			Province:           []string{"Tennessee"},
			Locality:           []string{"Nashville"},
			CommonName:         cname,
		},
		DNSNames:           []string{cname},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if addSAN {
		req.DNSNames = []string{cname}
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(csrBytes)
}

func signCSR(
	csr *x509.CertificateRequest,
	privKey *rsa.PrivateKey,
	signCert *x509.Certificate,
	signerURL string,
	isCA bool,
	multiMustStaple bool) (*x509.Certificate, error) {

	subjKeyID := make([]byte, 8)
	_, err := rand.Read(subjKeyID)
	if err != nil {
		panic(err)
	}
	extVal := MustStapleValue

	if multiMustStaple {
		extVal, _ = asn1.Marshal([]int{2, 3, 4, statusRequestExtension})
	}
	crtTmpl := &x509.Certificate{
		Signature:             csr.Signature,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SerialNumber:          NextSerial(),
		Subject:               csr.Subject,
		SubjectKeyId:          subjKeyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{signerURL},
		OCSPServer:            []string{"https://github.com/nathanejohnson/"},
		IsCA:                  isCA,
		DNSNames:              csr.DNSNames,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    MustStapleOID,
				Value: extVal,
			},
		},
	}
	if isCA {
		crtTmpl.KeyUsage = x509.KeyUsageCertSign
		crtTmpl.BasicConstraintsValid = true
	}

	if signCert == nil {
		// self signed root
		signCert = crtTmpl
	}

	signedRaw, err := x509.CreateCertificate(rand.Reader, crtTmpl, signCert, csr.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedRaw)
}

func NextSerial() *big.Int {
	serial++
	return big.NewInt(serial)
}

func genKeyAndMaybeWrite(keyPath string) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	if !writeFiles {
		return priv, nil
	}

	blck := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}

	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	err = pem.Encode(f, blck)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func writeCert(certPath string, asn1 []byte) error {
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: asn1})
}
