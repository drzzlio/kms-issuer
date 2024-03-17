// Some ideas from https://github.com/salrashid123/signer/blob/master/kms/kms.go
package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"sync"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Skyscanner/kms-issuer/v4/pkg/interfaces"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	refreshMutex = &sync.Mutex{}
	publicKey    crypto.PublicKey
)

type ClientFactory func(context.Context) (interfaces.KMSClient, error)

type KMS struct {
	crypto.Signer     // https://golang.org/pkg/crypto/#Signer
	KeyURI            string
	primaryVersionURI string
	// A kms client factory function, mainly useful for testing
	clientFactory ClientFactory
}

// Default client factory uses cloud KMS
func newCloudKmsClient(ctx context.Context) (interfaces.KMSClient, error) {
	return cloudkms.NewKeyManagementClient(ctx)
}

// Given the URI to a GCP KMS CryptoKey, validates and creates a KMS signer
// using the currently primary version of the key.
//
// The signature algorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS
func NewKMSCrypto(ctx context.Context, keyURI string) (crypto.Signer, error) {
	return NewKMSCryptoWithFactory(ctx, keyURI, newCloudKmsClient)
}

// Creates a new KMS signer using a given client factory, mainly useful when testing to mock out the kms interface
func NewKMSCryptoWithFactory(ctx context.Context, keyURI string, factory ClientFactory) (crypto.Signer, error) {
	// Validate inputs
	if keyURI == "" {
		return nil, fmt.Errorf("KeyURI cannot be empty")
	}

	// Get the current primary key version
	kmsClient, err := factory(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	key, err := kmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyURI})
	if err != nil {
		fmt.Printf("Error getting key %v", err)
		return nil, err
	}

	// Create the KMS instance
	kms := &KMS{
		KeyURI:            keyURI,
		primaryVersionURI: key.Primary.Name,
		clientFactory:     factory,
	}

	// Preload the public key
	publicKey, err = kms.getPublicKey(ctx, kmsClient)
	if err != nil {
		fmt.Printf("Error getting kms public key %v", err)
		return nil, err
	}

	// Give the enriched instance to the caller
	return kms, nil
}

func (t *KMS) getPublicKey(ctx context.Context, kmsClient interfaces.KMSClient) (crypto.PublicKey, error) {
	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: t.primaryVersionURI})
	if err != nil {
		fmt.Printf("Error getting GetPublicKey %v", err)
		return nil, err
	}
	pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))

	pub, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing PublicKey %v", err)
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// crypto.Signer.Public impl Gets the public key from the KMS w/memoization
func (t *KMS) Public() crypto.PublicKey {
	ctx := context.Background()
	if publicKey == nil {
		kmsClient, err := t.clientFactory(ctx)
		if err != nil {
			fmt.Printf("Error getting kms client %v", err)
			return nil
		}
		defer kmsClient.Close()

		publicKey, err = t.getPublicKey(ctx, kmsClient)
		if err != nil {
			fmt.Printf("Error getting kms public key %v", err)
			return nil
		}
	}

	return publicKey
}

// crypto.Signer.Sign impl signing a digest using the KMS private key
func (t *KMS) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("Sign: Digest length doesn't match passed crypto algorithm")
	}

	// Calculate digest crc32
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	digestCRC32C := crc32c(digest)

	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()

	kmsClient, err := t.clientFactory(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	pss, ok := opts.(*rsa.PSSOptions)
	if ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			fmt.Println("PSS salt length will automatically get set to rsa.PSSSaltLengthEqualsHash ")
		}
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: t.primaryVersionURI,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		fmt.Printf("Error signing with kms client %v", err)
		return nil, err
	}
	return dresp.Signature, nil
}
