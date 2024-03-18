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

package certmanager

import (
	"context"
	"fmt"

	kcck8s "github.com/GoogleCloudPlatform/k8s-config-connector/pkg/clients/generated/apis/k8s/v1alpha1"
	kcckms "github.com/GoogleCloudPlatform/k8s-config-connector/pkg/clients/generated/apis/kms/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

func emptyDefault(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func getKeyFromRef(ctx context.Context, kclient client.Client, issuerNS string, keyref kcck8s.ResourceRef) (string, error) {
	// validation
	if keyref.External == "" && keyref.Name == "" {
		return "", fmt.Errorf("the KeyRef must specify at least `External` or `Name`")
	}
	if keyref.External != "" && keyref.Name != "" {
		return "", fmt.Errorf("the KeyRef must specify only one of `External` or `Name`")
	}

	keyURI := keyref.External
	if keyURI == "" {
		var key kcckms.KMSCryptoKey
		keyapiname := types.NamespacedName{
			Name:      keyref.Name,
			Namespace: emptyDefault(keyref.Namespace, issuerNS),
		}
		// Find the key in the k8s API
		if err := kclient.Get(ctx, keyapiname, &key); err != nil {
			return "", fmt.Errorf("failed to get key referenced in KeyRef %s", keyapiname)
		}
		// SelfLink is the GCP KMS API path to the actual key
		if key.Status.SelfLink != nil {
			keyURI = *key.Status.SelfLink
		} else {
			// Can happen if the config controller hasn't finished creating the key in KMS yet
			return "", fmt.Errorf("key has no SelfLink yet")
		}
	}

	return keyURI, nil
}
