package intransport

import (
	"crypto/x509"
	"sync"
)

// LockedCachedCertRepresenter - awkwardly named interface for a cached and locked certificate entry.
type LockedCachedCertRepresenter interface {
	// Cert is the getter function and will be called on a locked entry.
	// A nil value is valid as a return, and signals we need to fetch the certificate.
	Cert() *x509.Certificate

	// SetCert is the certificate setter function and will be called on a locked entry.
	SetCert(cert *x509.Certificate)

	// Unlock will be called after fetching and / or setting the value.  Once Unlock is called,
	// no other calls will be made.  For subsequent access, Cacher.LockedCachedCert will be called again.
	Unlock()
}

// Cacher - interface for caching x509 entries.
type Cacher interface {
	// LockedCachedCert will be called for a key, and this should
	// return a locked entry.
	LockedCachedCert(key string) LockedCachedCertRepresenter
}

type certCacheEntry struct {
	sync.Mutex
	cert *x509.Certificate
}

func (cce *certCacheEntry) Cert() *x509.Certificate {
	return cce.cert
}

func (cce *certCacheEntry) SetCert(cert *x509.Certificate) {
	cce.cert = cert
}

type certCache struct {
	sync.Mutex
	m map[string]*certCacheEntry
}

// NewMapCache - returns a Cacher implementation based on a go map and mutexes.
func NewMapCache() Cacher {
	return &certCache {
		m: make(map[string]*certCacheEntry),
	}
}

func (cc *certCache) LockedCachedCert(key string) LockedCachedCertRepresenter {
	cc.Lock()
	cce, ok := cc.m[key]
	if ok {
		cc.Unlock()
		cce.Lock()
		return cce
	}

	// cache miss
	cce = &certCacheEntry{}
	cce.Lock()
	cc.m[key] = cce
	cc.Unlock()
	return cce
}

type nopCache struct {}

type nopCacheEntry struct {}

// NewNopCache - this returns a nop cache, which can be used to disable caching of certificates.
func NewNopCache() Cacher {
	return nopCache{}
}

func (nc nopCache) LockedCachedCert(_ string) LockedCachedCertRepresenter {
	return nopCacheEntry{}
}

func (nce nopCacheEntry) LockEntry() {
	return
}

func (nce nopCacheEntry) Unlock() {
	return
}

func (nce nopCacheEntry) UnlockCacher() {
	return
}

func (nce nopCacheEntry) Cert() *x509.Certificate {
	return nil
}

func (nce nopCacheEntry) SetCert(_ *x509.Certificate) {
	return
}
