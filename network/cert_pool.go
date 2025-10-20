/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package network

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// CertPoolBuilder contains the data and logic needed to create a certificate pool. Don't create instances of
// this object directly, use the NewCertPoolBuilder function instead.
type CertPoolBuilder struct {
	logger          *slog.Logger
	systemFiles     bool
	kubernetesFiles bool
	files           []string
}

// NewCertPool creates a builder that can then used to configure and create a certificate pool.
func NewCertPool() *CertPoolBuilder {
	return &CertPoolBuilder{}
}

// SetLogger sets the logger that the loader will use to send messages to the log. This is mandatory.
func (b *CertPoolBuilder) SetLogger(value *slog.Logger) *CertPoolBuilder {
	b.logger = value
	return b
}

// AddSystemFiles adds the system files to the pool. The default is to add them.
func (b *CertPoolBuilder) AddSystemFiles(value bool) *CertPoolBuilder {
	b.systemFiles = value
	return b
}

// AddKubernertesFiles adds the Kubernetes CA files to the pool. The default is to add them.
func (b *CertPoolBuilder) AddKubernertesFiles(value bool) *CertPoolBuilder {
	b.kubernetesFiles = value
	return b
}

// AddFile adds a file containing CA certificates to be loaded into the pool. This is optional.
func (b *CertPoolBuilder) AddFile(value string) *CertPoolBuilder {
	b.files = append(b.files, value)
	return b
}

// AddFiles adds multiple files containing CA certificates to be loaded into the pool. This is optional.
func (b *CertPoolBuilder) AddFiles(values ...string) *CertPoolBuilder {
	b.files = append(b.files, values...)
	return b
}

// Build uses the data stored in the builder to create a new certificate pool.
func (b *CertPoolBuilder) Build() (result *x509.CertPool, err error) {
	// Check parameters:
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}

	// Start with an empty pool, or with a copy of the system pool if the system files are enabled:
	var pool *x509.CertPool
	if b.systemFiles {
		pool, err = x509.SystemCertPool()
		if err != nil {
			return
		}
	} else {
		pool = x509.NewCertPool()
	}

	// Add Kubernetes CA files if enabled:
	if b.kubernetesFiles {
		err = b.loadKubernetesCaFiles(pool)
		if err != nil {
			return
		}
	}

	// Load configured CA files:
	err = b.loadConfiguredCaFiles(pool)
	if err != nil {
		return
	}

	result = pool
	return
}

func (b *CertPoolBuilder) loadKubernetesCaFiles(pool *x509.CertPool) error {
	for _, caFile := range certPoolKubernetesCaFiles {
		err := b.loadCaFile(pool, caFile)
		if errors.Is(err, os.ErrNotExist) {
			b.logger.Info(
				"Kubernetes CA file doesn't exist",
				slog.String("file", caFile),
			)
			err = nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *CertPoolBuilder) loadConfiguredCaFiles(pool *x509.CertPool) error {
	for _, caFile := range b.files {
		err := b.loadCaFile(pool, caFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *CertPoolBuilder) loadCaFile(pool *x509.CertPool, caFile string) error {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA file '%s': %w", caFile, err)
	}
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return fmt.Errorf("file exists, but it '%s' doesn't contain any CA certificate", caFile)
	}
	b.logger.Info(
		"Loaded CA file",
		slog.String("file", caFile),
	)
	return nil
}

// certPoolLoaderKubernetesCaFiles is a list of Kubernetes CA files that will be automatically loaded if they exist.
var certPoolKubernetesCaFiles = []string{
	// This is the CA used for Kubernetes to sign the certificates of service accounts.
	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",

	// This is the CA used by OpenShift to sign the certificates generated for services.
	"/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt",
}
