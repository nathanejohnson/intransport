package intransport

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestBadSiteWithError(t *testing.T) {
	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}
	resp, err := c.Get("https://www.ena.com/")
	if err == nil {
		t.Log("error was nil")
		io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fail()
	} else {
		t.Log("error returned was: ", err)
	}
}

func TestBadSiteFetchIntermediates(t *testing.T) {
	c := NewInTransportClient()
	resp, err := c.Get("https://www.ena.com/")
	if err == nil {
		site, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error("ReadAll failed unexpectedly ", err)
			t.Fail()
		}
		_ = resp.Body.Close()
		t.Log(string(site))
	}
}
