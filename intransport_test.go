package intransport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
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

	err = os.Mkdir(hostDir, 0755)
	if err != nil {
		return err
	}
	return nil
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
	rootPriv, err = genKeyAndWrite(filepath.Join(basePath, "rootCA.key"))
	if err != nil {
		return
	}

	var csr *x509.CertificateRequest
	csr, err = makeCSR("Mister Sunshine's Root CA", rootPriv)
	if err != nil {
		return
	}
	var rootCert *x509.Certificate

	rootCert, err = signCSR(csr, rootPriv, nil, "", true)
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
		priv, err = genKeyAndWrite(filepath.Join(intDir, fileName))
		if err != nil {
			return
		}

		var csr *x509.CertificateRequest
		csr, err = makeCSR(fmt.Sprintf("%s intermediate CA", icn), priv)
		if err != nil {
			return
		}
		var intCrt *x509.Certificate

		intCrt, err = signCSR(csr, rootPriv, rootCert, rootIntM.caIssuerURL, true)

		if err != nil {
			return
		}

		certFileName := icn + ".crt"
		if writeFiles {
			err = writeCert(filepath.Join(intDir, certFileName), intCrt.Raw)
		}

		if err != nil {
			return
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
			priv, err = genKeyAndWrite(filepath.Join(hostDir, fileName))
			if err != nil {
				return
			}
			csr, err = makeCSR(hcn, priv)
			if err != nil {
				return
			}
			var crt *x509.Certificate
			crt, err = signCSR(csr, inm.privKey, inm.cert, inm.caIssuerURL, false)
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

			_ = ocspResp

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
	c := NewInTransportHTTPClient(&tls.Config{RootCAs: rootPool})
	it := c.Transport.(*InTransport)
	it.NextVerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		t.Logf("Chain length: %d", len(verifiedChains))
		for i, chain := range verifiedChains {
			t.Logf("chain %d length: %d", i, len(chain))
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
	for hname, s := range hostServers {
		t.Logf("doing %s", hname)
		surl, _ := url.Parse(s.URL)
		port := surl.Port()
		surl.Host = fmt.Sprintf("%s:%s", hname, port)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(hname string, serverURL string) {
				defer func() {
					wg.Done()
				}()
				t.Logf("fetching %s", serverURL)
				resp, err := c.Get(serverURL)
				if err != nil {
					t.Errorf("got error on %s: %s", hname, err)
					t.Fail()
					return
				}
				b, err := ioutil.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Errorf("got error reading from response: %s: %s", hname, err)
					t.Fail()
					return
				}
				t.Logf("response from %s: %s", hname, string(b))
			}(hname, surl.String())
		}
	}
	wg.Wait()

}

func makeCSR(cname string, priv *rsa.PrivateKey) (request *x509.CertificateRequest, err error) {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Version: 0,
			Subject: pkix.Name{
				Organization:       []string{"Mister Sunshine's fun shop"},
				OrganizationalUnit: []string{"R&D"},
				Country:            []string{"US"},
				Province:           []string{"Tennessee"},
				Locality:           []string{"Nashville"},
				CommonName:         cname,
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
		priv)
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
	isCA bool) (*x509.Certificate, error) {

	subjKeyID := make([]byte, 8)
	_, err := rand.Read(subjKeyID)
	if err != nil {
		panic(err)
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
		ExtraExtensions: []pkix.Extension{
			{
				Id:    MustStapleOID,
				Value: MustStapleValue,
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

func genKeyAndWrite(keyPath string) (*rsa.PrivateKey, error) {
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
