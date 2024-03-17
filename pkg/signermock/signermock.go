// Some ideas from https://github.com/salrashid123/signer/blob/master/pem/pem.go
package signermock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"sync"
)

const (
	KEYSIZE = 2048
)

type MockSigner struct {
	KeyURI string
	Key    *rsa.PrivateKey
	mu     sync.Mutex
}

func NewMockSigner(_ context.Context, keyURI string) (crypto.Signer, error) {
	if keyURI == "" {
		return nil, fmt.Errorf("KeyURI cannot be empty")
	}

	// Generate an RSA key
	key, err := rsa.GenerateKey(rand.Reader, KEYSIZE)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key")
	}

	return &MockSigner{
		KeyURI: keyURI,
		Key:    key,
	}, nil
}

func (t *MockSigner) Public() crypto.PublicKey {
	return t.Key.Public()
}

func (t *MockSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("Sign: Digest length doesn't match passed crypto algorithm")
	}

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}

	// RSA-PSS: https://github.com/golang/go/issues/32425
	var ropts rsa.PSSOptions
	ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	signature, err := rsa.SignPSS(rand.Reader, t.Key, opts.HashFunc(), digest, &ropts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
	}

	return signature, nil
}
