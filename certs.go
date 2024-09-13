// Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tapir

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

type Config struct {
	CAFile   string `validate:"existing-file-ro"`
	KeyFile  string `validate:"existing-file-ro"`
	CertFile string `validate:"existing-file-ro"`
}

type SimpleConfig struct {
	CAFile string `validate:"existing-file-ro"`
}

func loadCertPool(filename string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, nil
}

// Create a tls.Config for a server.
// clientAuth: tls.NoClientCert                => Accept any client.
// clientAuth: tls.RequireAndVerifyClientCert  => Only accept client with valid cert.
func NewServerConfig(caFile string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: clientAuth,
		NextProtos: []string{"h2", "http/1.1"},
	}

	return config, nil
}

func NewClientConfig(caFile, keyFile, certFile string) (*tls.Config, error) {

	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return config, nil
}

// NewSimpleClientConfig creates a TLS config with a common CA cert,
// specified in caFile, but without a client certificate.
func NewSimpleClientConfig(caFile string) (*tls.Config, error) {
	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		RootCAs: caCertPool,
	}

	return config, nil
}
