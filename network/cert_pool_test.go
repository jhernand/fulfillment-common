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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate pool", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error

		// Create a temporary directory:
		tmpDir, err = os.MkdirTemp("", "*.test")
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := os.RemoveAll(tmpDir)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	// makeCerts creates a CA certificate and a TLS certificates signed by that CA. Returns the location of the CA
	// certificate and the locations of the TLS certificate and private key, all in PEM format.
	makeCerts := func(name string) (caCertFile, tlsCertFile, tlsKeyFile string) {
		// Generate the CA key pair:
		caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
		caPublicKey := &caPrivateKey.PublicKey

		// Create the CA certificate:
		caDate := time.Now()
		caCert := x509.Certificate{
			SerialNumber: big.NewInt(0),
			Subject: pkix.Name{
				CommonName: name,
			},
			NotBefore:             caDate,
			NotAfter:              caDate.AddDate(10, 0, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			MaxPathLen:            2,
		}

		// Sign the CA certificate:
		caDer, err := x509.CreateCertificate(rand.Reader, &caCert, &caCert, caPublicKey, caPrivateKey)
		Expect(err).ToNot(HaveOccurred())

		// PEM encode the CA certificate:
		caPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caDer,
		})

		// Save the CA certificate to a temporary file:
		caCertFile = filepath.Join(tmpDir, name+".pem")
		err = os.WriteFile(caCertFile, caPem, 0600)
		Expect(err).ToNot(HaveOccurred())

		// Generate the TLS key pair:
		tlsPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())
		tlsPublicKey := &tlsPrivateKey.PublicKey

		// Create the TLS certificate:
		tlsCert := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "localhost",
			},
			NotBefore: caDate,
			NotAfter:  caDate.AddDate(10, 0, 0),
			KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
			DNSNames:              []string{"localhost"},
			IPAddresses: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("::1"),
			},
		}

		// Sign the TLS certificate with the CA:
		tlsDer, err := x509.CreateCertificate(rand.Reader, &tlsCert, &caCert, tlsPublicKey, caPrivateKey)
		Expect(err).ToNot(HaveOccurred())

		// PEM encode the TLS certificate:
		tlsPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsDer,
		})

		// Save the TLS certificate to a temporary file:
		tlsCertFile = filepath.Join(tmpDir, name+"-tls.pem")
		err = os.WriteFile(tlsCertFile, tlsPem, 0600)
		Expect(err).ToNot(HaveOccurred())

		// PEM encode the TLS private key:
		tlsKeyPem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(tlsPrivateKey),
		})

		// Save the TLS private key to a temporary file:
		tlsKeyFile = filepath.Join(tmpDir, name+"-tls-key.pem")
		err = os.WriteFile(tlsKeyFile, tlsKeyPem, 0600)
		Expect(err).ToNot(HaveOccurred())

		return
	}

	Describe("Creation", func() {
		It("Fails if logger is not set", func() {
			pool, err := NewCertPool().
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("logger is mandatory"))
			Expect(pool).To(BeNil())
		})

		It("Can be created without adding any files", func() {
			pool, err := NewCertPool().
				SetLogger(logger).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(pool).ToNot(BeNil())
		})

		It("Can be created with one file", func() {
			// Create one CA file:
			myCa, _, _ := makeCerts("My CA")

			// Create the pool:
			pool, err := NewCertPool().
				SetLogger(logger).
				AddFile(myCa).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(pool).ToNot(BeNil())
		})

		It("Can be created with multiple files", func() {
			// Create two CA files:
			myCa, _, _ := makeCerts("My CA")
			yourCa, _, _ := makeCerts("Your CA")

			// Create the pool:
			pool, err := NewCertPool().
				SetLogger(logger).
				AddFiles(myCa, yourCa).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(pool).ToNot(BeNil())
		})

		It("Can't be created with files that don't exist", func() {
			// Create a path for a flie that doesn't exist:
			doesNotExist := filepath.Join(tmpDir, "does-not-exist.pem")

			// Create the pool:
			pool, err := NewCertPool().
				SetLogger(logger).
				AddFile(doesNotExist).
				Build()
			Expect(err).To(HaveOccurred())
			message := err.Error()
			Expect(message).To(ContainSubstring("failed to read CA file"))
			Expect(message).To(ContainSubstring("does-not-exist.pem"))
			Expect(message).To(ContainSubstring("no such file or directory"))
			Expect(pool).To(BeNil())
		})

		It("Can't be created with files that don't contain valid certificates", func() {
			// Create a file with invalid content:
			junkFile := filepath.Join(tmpDir, "junk.pem")
			err := os.WriteFile(junkFile, []byte("junk"), 0600)
			Expect(err).ToNot(HaveOccurred())

			// Create the pool:
			pool, err := NewCertPool().
				SetLogger(logger).
				AddFile(junkFile).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("doesn't contain any CA certificate"))
			Expect(pool).To(BeNil())
		})
	})

	Describe("Behavior", func() {
		It("Can be used to connect to a TLS server", func() {
			// Create the certificates:
			caFile, certFile, keyFile := makeCerts("My CA")
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			Expect(err).ToNot(HaveOccurred())

			// Create the listener:
			rawListener, err := net.Listen("tcp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			defer func() {
				err := rawListener.Close()
				Expect(err).ToNot(HaveOccurred())
			}()
			tlsListener := tls.NewListener(
				rawListener, &tls.Config{
					Certificates: []tls.Certificate{cert},
				})
			go func() {
				defer GinkgoRecover()
				conn, err := tlsListener.Accept()
				Expect(err).ToNot(HaveOccurred())
				defer func() {
					err := conn.Close()
					Expect(err).ToNot(HaveOccurred())
				}()
				_, err = conn.Write([]byte("Hello!"))
				Expect(err).ToNot(HaveOccurred())
			}()

			// Create the pool:
			pool, err := NewCertPool().
				SetLogger(logger).
				AddFile(caFile).
				Build()
			Expect(err).ToNot(HaveOccurred())
			Expect(pool).ToNot(BeNil())

			// Verify the TLS handshake completes successfully:
			conn, err := tls.Dial(
				"tcp",
				tlsListener.Addr().String(),
				&tls.Config{
					RootCAs:    pool,
					ServerName: "localhost",
				},
			)
			Expect(err).ToNot(HaveOccurred())
			defer func() {
				err := conn.Close()
				Expect(err).ToNot(HaveOccurred())
			}()
			err = conn.Handshake()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
