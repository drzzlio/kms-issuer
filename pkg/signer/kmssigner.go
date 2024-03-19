/*
Copyright 2020 Skyscanner Limited.
Copyright 2023 Josh Perry

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
	"github.com/drzzlio/kms-issuer/v1/pkg/interfaces"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	refreshMutex = &sync.Mutex{}
)

type ClientFactory func(context.Context) (interfaces.KMSClient, error)

type KMS struct {
	crypto.Signer // https://golang.org/pkg/crypto/#Signer
	KeyURI        string
	publicKey     crypto.PublicKey
	// A kms client factory function, mainly useful for testing
	clientFactory ClientFactory
}

// Default client factory uses cloud KMS
func newCloudKmsClient(ctx context.Context) (interfaces.KMSClient, error) {
	return cloudkms.NewKeyManagementClient(ctx)
}

// Given the URI to a GCP KMS CryptoKey, validates and creates a KMS signer
// using the currently primary version of the key.
func NewKMSCrypto(ctx context.Context, keyURI string) (crypto.Signer, error) {
	return NewKMSCryptoWithFactory(ctx, keyURI, newCloudKmsClient)
}

// Creates a new KMS signer using a given client factory, mainly useful when testing to mock out the kms interface
func NewKMSCryptoWithFactory(ctx context.Context, keyURI string, factory ClientFactory) (crypto.Signer, error) {
	// Validate inputs
	if keyURI == "" {
		return nil, fmt.Errorf("KeyURI cannot be empty")
	}

	// Create the KMS instance
	kms := &KMS{
		// Always version 1; if you want a different key, make a new key.
		KeyURI:        fmt.Sprintf("%s/cryptoKeyVersions/1", keyURI),
		clientFactory: factory,
	}

	// Client to get the public key
	kmsClient, err := factory(ctx)
	if err != nil {
		fmt.Printf("Error getting kms client %v", err)
		return nil, err
	}
	defer kmsClient.Close()

	// Get the public key in pem format
	dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: kms.KeyURI})
	if err != nil {
		fmt.Printf("Error getting GetPublicKey %v", err)
		return nil, err
	}

	// Decode the pem into an x509 public key
	pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))
	pubkey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing PublicKey %v", err)
		return nil, err
	}
	kms.publicKey = pubkey

	// Give the KMS instance to the caller
	return kms, nil
}

// crypto.Signer.Public impl Gets the public key retrieved from the KMS
func (t *KMS) Public() crypto.PublicKey {
	return t.publicKey
}

// crypto.Signer.Sign impl signing a digest using the KMS API which holds the private key
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
		Name: t.KeyURI,
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
