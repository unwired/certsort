// Copyright 2023 Brendan Abolivier
// Copyright 2023 Unwired Networks GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certsort

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

type certType int

const (
	// CertTypeRootCA is a CA certificate that is signed by itself.
	CertTypeRootCA certType = iota
	// CertTypeIntermediateCA is a CA certificate that is not signed by itself.
	CertTypeIntermediateCA
	// CertTypeClientCert is a certificate that is not a CA certificate.
	CertTypeClientCert
)

var (
	// ErrParallelChains is returned when multiple parallel verification chains are
	// detected. For example, if certificates A and B are both parents of certificate C,
	// or if certificates B and C are both leaves of certificate A.
	ErrParallelChains = errors.New("multiple parallel verification chains detected")
	// ErrNilLeafCertificate is returned when trying to set a nil certificate as the leaf
	// of another certificate.
	ErrNilLeafCertificate = fmt.Errorf("proposed leaf certificate is nil")
	// ErrCertificatePKeyAlgoUnsupported is returned when trying to instantiate a
	// Certificate with a public key algorithm that is not supported.
	ErrCertificatePKeyAlgoUnsupported = fmt.Errorf("certificate's public key algorithm is not supported")
)

// Certificate is a node in a CertChain which wraps around an X509 certificate.
type Certificate struct {
	// The underlying X509 certificate.
	C *x509.Certificate
	// The node's parent.
	Parent *Certificate
	// The node's leaf.
	Leaf *Certificate
	// The type of certificate.
	Type certType
	// Optional label associated with the node, for testing purposes.
	label *string
}

// NewCertificate instantiates a new Certificate from an *x509.Certificate, checks that
// its public key is using a supported algorithm, and infers its type (root CA,
// intermediate CA, client-facing).
// Also takes a label, which is associated to the certificate for use in testing.
// Returns an error if the public key's algorithm is not supported.
func NewCertificate(cert *x509.Certificate, label *string) (*Certificate, error) {
	// Instantiate a new certificate.
	c := &Certificate{
		C:     cert,
		label: label,
	}

	// Check that the certificate's public key algorithm is supported.
	// We do not support DSA keys, as they are considered deprecated because of their low security.
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm || cert.PublicKeyAlgorithm == x509.DSA {
		return nil, ErrCertificatePKeyAlgoUnsupported
	}

	// Infers the type of the certificate based on its signature and its CA flag.
	if c.IsSignedBy(c) {
		c.Type = CertTypeRootCA
	} else if c.C.IsCA {
		c.Type = CertTypeIntermediateCA
	} else {
		c.Type = CertTypeClientCert
	}

	return c, nil
}

// Bytes returns the raw Bytes for the current certificate, which can then be encoded into
// a PEM block.
func (c *Certificate) Bytes() []byte {
	return c.C.Raw
}

// cacheKey returns a string that is theoretically unique to the current certificate.
// The generated key is a concatenation of the issuer's serial number and of the
// certificate's serial number. The uniqueness of the resulting string is assumed from
// the fact that a certificate's serial number is expected to be unique within a given CA.
func (c *Certificate) cacheKey() string {
	return fmt.Sprintf("%s-%s", c.C.Issuer.SerialNumber, c.C.SerialNumber.Bytes())
}

// IsSignedBy checks whether the current certificate is signed by the given certificate,
// i.e. if the provided one is a parent of the current one in the verification chain.
func (c *Certificate) IsSignedBy(p *Certificate) bool {
	if p == nil {
		// If the proposed parent is nil, return false.
		return false
	}

	return c.C.CheckSignatureFrom(p.C) == nil
}

// SetLeaf sets the given certificate as a leaf of the current one, and sets the current
// one as a parent of the provided one.
// Returns ErrParallelChains if either the current certificate already has a leaf, or the
// provided one already has a parent, because this means that there are multiple parallel
// chains in the set we are currently processing, which is not currently supported.
func (c *Certificate) SetLeaf(l *Certificate) error {
	if l == nil {
		return ErrNilLeafCertificate
	}

	// If the proposed new leaf already has a parent, or the current certificate already
	// has a leaf, it likely means there's a parallel validation chain (since we've
	// already taken care of eliminating duplicates).
	if c.Leaf != nil || l.Parent != nil {
		return ErrParallelChains
	}

	c.Leaf = l
	l.Parent = c

	return nil

}

// PublicKey returns the public key for the current certificate.
func (c *Certificate) PublicKey() crypto.PublicKey {
	// We should be able to correctly assert the type of the public key here since
	// we've already checked that the algorithm is supported in NewCertificate.
	return c.C.PublicKey
}

// CertChain represents a linear linked chain of x509 certificates in which each
// certificate is verified by the one preceding it (going from the root to the furthest
// leaf).
type CertChain struct {
	// The chain's root certificate.
	Root *Certificate
	// The chain's leaf certificate that is the furthest away from the root.
	FurthestLeaf *Certificate
	// Certificate chains that cannot be linked to the main chain at the time these
	// certificates are being processed. Once every certificate has been read, an
	// additional cleanup is done to try to attach any orphan that can be to the main
	// chain.
	// Ignored if the chain itself is an orphan.
	Orphans []*CertChain
	// Shows whether this chain is an orphan chain or the main certificate chain.
	// If set to true, the Orphans slice should be ignored.
	isOrphaned bool
	// A map of all certificates that have been recorded either as part of the main chain
	// or as an orphan.
	knownCertificates map[string]*Certificate
}

// NewCertChain instantiates a new certificate chain.
func NewCertChain() *CertChain {
	return &CertChain{
		Orphans:           make([]*CertChain, 0),
		knownCertificates: make(map[string]*Certificate),
	}
}

// newOrphanChainFromCert instantiates a new orphaned chain from the given certificate
// (which couldn't be added to either the main chain or an existing orphan chain).
func newOrphanChainFromCert(c *Certificate) *CertChain {
	return &CertChain{
		Root:         c,
		FurthestLeaf: c,
		isOrphaned:   true,
	}
}

// Len calculate the length of the current certificate chain.
func (cc *CertChain) Len() int {
	i := 0
	c := cc.Root
	for c != nil {
		i++
		c = c.Leaf
	}
	return i
}

// CountOrphans counts the remaining orphans in the current chain.
func (cc *CertChain) CountOrphans() int {
	i := 0
	for _, orphan := range cc.Orphans {
		if orphan.isOrphaned {
			i++
		}
	}

	return i
}

// AddFromBytes parses the given DER bytes (usually read from a PEM block) as a x509
// certificate, and adds it to the chain.
// Also takes an optional label to associate with the certificate once parsed, to use for
// testing.
func (cc *CertChain) AddFromBytes(b []byte, label *string) error {
	// Try to parse the certificate.
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return err
	}

	c, err := NewCertificate(cert, label)
	if err != nil {
		return err
	}

	if _, known := cc.knownCertificates[c.cacheKey()]; known {
		// This is a duplicate of a certificate we have already processed - ignore.
		return nil
	}

	// If the root hasn't been set, we haven't started processing any certificate, so
	// this one is both our root and our furthest leaf.
	if cc.Root == nil {
		cc.Root = c
		cc.FurthestLeaf = c
	} else {
		success, err := cc.AddToChain(c)
		if err != nil {
			return err
		}

		if !success {
			// If we couldn't fit the certificate anywhere in the chain, then we record it
			// as an orphan.
			if err = cc.addToOrphanChain(c); err != nil {
				return err
			}
		}
	}

	// Record the certificate as known, so we don't process duplicates if there are any.
	cc.knownCertificates[c.cacheKey()] = c

	return nil
}

// insertChainBefore inserts the given orphan chain at the start of the current chain.
func (cc *CertChain) insertChainBefore(orphan *CertChain) error {
	if err := orphan.FurthestLeaf.SetLeaf(cc.Root); err != nil {
		return err
	}
	cc.Root = orphan.Root
	return nil
}

// insertChainAfter inserts the given orphan chain at the end of the current chain.
func (cc *CertChain) insertChainAfter(orphan *CertChain) error {
	if err := cc.FurthestLeaf.SetLeaf(orphan.Root); err != nil {
		return err
	}
	cc.FurthestLeaf = orphan.FurthestLeaf
	return nil
}

// simplifyOrphanChains iterates over the recorded orphan chains for the current chain,
// and tries to merge them when possible.
// If there are less than 2 orphan chains, returns immediately.
func (cc *CertChain) simplifyOrphanChains() error {
	if len(cc.Orphans) <= 1 {
		// If we've only got one orphan chain or less, we can ignore this process because
		// there's nothing to simplify.
		return nil
	}

	// Iterate over the orphan chain.
	for _, chain := range cc.Orphans {
		if !chain.isOrphaned {
			// Don't try to process chains that are not orphans anymore.
			continue
		}
		// For each chain, try to link it against each other orphan.
		for _, otherchain := range cc.Orphans {
			if !otherchain.isOrphaned {
				// Don't try to process chains that are not orphans anymore.
				continue
			}

			if otherchain.Root.IsSignedBy(chain.FurthestLeaf) {
				otherchain.isOrphaned = false
				if err := chain.insertChainAfter(otherchain); err != nil {
					return err
				}
			} else if otherchain.FurthestLeaf.IsSignedBy(chain.Root) {
				chain.isOrphaned = false
				if err := chain.insertChainBefore(otherchain); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// Cleanup first tries to simplify the orphan chains on the current chain, then tries to
// reattach any remaining orphan to the main chain.
func (cc *CertChain) Cleanup() error {
	if err := cc.simplifyOrphanChains(); err != nil {
		return err
	}

	// Try reattaching remaining orphans to the main chain.
	for _, orphan := range cc.Orphans {
		if !orphan.isOrphaned {
			// Don't try to process chains that are not orphans anymore.
			continue
		}

		if orphan.Root.IsSignedBy(cc.FurthestLeaf) {
			orphan.isOrphaned = false
			if err := cc.insertChainAfter(orphan); err != nil {
				return err
			}
		} else if cc.Root.IsSignedBy(orphan.FurthestLeaf) {
			orphan.isOrphaned = false
			if err := cc.insertChainBefore(orphan); err != nil {
				return err
			}
		}
	}

	return nil
}

// addToOrphanChain attempts to fit the given certificate into an existing orphan chain.
// If it can't, creates a new chain with only this certificate and add it to the list of
// orphans.
func (cc *CertChain) addToOrphanChain(c *Certificate) error {
	for _, chain := range cc.Orphans {
		success, err := chain.AddToChain(c)
		if success || err != nil {
			// If success is true, err should be nil. We want to return here in this case
			// too, so might as well return in one condition rather than two.
			return err
		}
	}

	cc.Orphans = append(cc.Orphans, newOrphanChainFromCert(c))

	return nil
}

// AddToChain tries to add the given certificate to the current chain.
// Returns a boolean indicating whether the certificate could be fitted onto the current
// chain. If it couldn't (i.e. the return value is false), then the certificate must be
// added to an orphan chain.
func (cc *CertChain) AddToChain(c *Certificate) (bool, error) {
	if c.IsSignedBy(cc.Root) {
		// If the certificate has been signed by the chain's root, then it's a direct
		// leaf of it. Since we're handling only one verification chain, it's also the
		// new furthest leaf.
		if err := cc.Root.SetLeaf(c); err != nil {
			return false, err
		}
		cc.FurthestLeaf = c
	} else if c.IsSignedBy(cc.FurthestLeaf) {
		// If the certificate has been signed by the chain's furthest leaf, then it's
		// a direct leaf of it. It's also the new furthest leaf.
		if err := cc.FurthestLeaf.SetLeaf(c); err != nil {
			return false, err
		}
		cc.FurthestLeaf = c
	} else if cc.Root.IsSignedBy(c) {
		// If the chain's root has been signed by the certificate, then it's a direct
		// leaf of it, and the certificate is the chain's new root.
		if err := c.SetLeaf(cc.Root); err != nil {
			return false, err
		}
		cc.Root = c
	} else {
		return false, nil
	}

	return true, nil
}
