[![GoDoc](https://godoc.org/github.com/nathanejohnson/intransport?status.svg)](https://godoc.org/github.com/nathanejohnson/intransport)
[![Go Report Card](https://goreportcard.com/badge/github.com/nathanejohnson/intransport)](https://goreportcard.com/report/github.com/nathanejohnson/intransport)
[![Build Status](https://api.travis-ci.org/nathanejohnson/intransport.svg?branch=master)](https://travis-ci.org/nathanejohnson/intransport)


This is go http transport / client that will fetch intermediate certificates as needed.  Additionally, this will verify
stapled OCSP responses.  In the event that a certificate is marked with must staple, a missing
stapled OCSP in the response will cause an error.

see https://tools.ietf.org/html/rfc7633

In order to use this, for most use cases, will be simply:

```go
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	
	it "github.com/nathanejohnson/intransport"
)

func main() {
	c := it.NewInTransportHTTPClient(nil)
	resp, err := c.Get("https://something.org")
	if err != nil {
		fmt.Println("boo, hiss! ", err)
		os.Exit(1)
	}
	body, err := ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {		
		fmt.Println("ba dum, tiss! ", err)
		os.Exit(1)
	}
	fmt.Printf("got response:\n%s", string(body))
}
```



