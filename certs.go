/*
 * Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
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

func FetchTapirClientCert(lg *log.Logger, statusch chan<- ComponentStatusUpdate) (string, *x509.CertPool, *tls.Certificate, error) {
	clientCertFile := viper.GetString("tapir.mqtt.clientcert")
	if clientCertFile == "" {
		return "", nil, nil, fmt.Errorf("MQTT client cert file not specified in config")
	}

	clientKeyFile := viper.GetString("tapir.mqtt.clientkey")
	if clientKeyFile == "" {
		return "", nil, nil, fmt.Errorf("MQTT client key file not specified in config")
	}

	cacertFile := viper.GetString("tapir.mqtt.cacert")
	if cacertFile == "" {
		return "", nil, nil, fmt.Errorf("MQTT CA cert file not specified in config")
	}

	// Setup CA cert for validating the MQTT connection
	cacertFile = filepath.Clean(cacertFile)
	caCert, err := os.ReadFile(cacertFile)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to read CA certificate in file %s: %w", cacertFile, err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		return "", nil, nil, fmt.Errorf("failed to parse CA certificate in file %s", cacertFile)
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to load client certificate in file %s: %w", clientCertFile, err)
	}

	// Parse the certificate to get the Common Name (CN)
	cert, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}
	commonName := cert.Subject.CommonName
	log.Printf("Client certificate Common Name (CN): %s", commonName)

	// Check if the client certificate is expiring soon (less than a month away)
	now := time.Now()
	expirationDays := viper.GetInt("certs.expirationwarning")
	if expirationDays == 0 {
		expirationDays = 30
	}
	expirationWarningThreshold := now.AddDate(0, 0, expirationDays)
	if clientCert.Leaf == nil {
		// Parse the certificate if Leaf is not available
		cert, err := x509.ParseCertificate(clientCert.Certificate[0])
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to parse client certificate: %w", err)
		}
		clientCert.Leaf = cert
	}
	log.Printf("*** Parsed DNS TAPIR client cert (from file %s):", clientCertFile)

	for _, cert := range clientCert.Certificate {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to parse client certificate: %w", err)
		}
		log.Printf("*** Subject: %s, Issuer: %s", cert.Subject, cert.Issuer)
	}

	if clientCert.Leaf.NotAfter.Before(expirationWarningThreshold) {
		msg := fmt.Sprintf("Client certificate will expire on %v (< %d days away)", clientCert.Leaf.NotAfter.Format(TimeLayout), expirationDays)
		lg.Printf("WARNING: %s", msg)
		statusch <- ComponentStatusUpdate{
			Component: "cert-status",
			Status:    StatusWarn,
			Msg:       msg,
			TimeStamp: time.Now(),
		}
	}

	// Check if any of the CA certificates are expiring soon
	block, _ := pem.Decode([]byte(caCert))
	if block == nil {
		return "", nil, nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}
	// log.Printf("Parsed CA cert: %+v", block)
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse CA certificates in file %s: %w", cacertFile, err)
	}

	for _, caCert := range certs {
		log.Printf("*** Parsed DNS TAPIR CA cert (from file %s):\n*** Issuer: %s, Subject: %s",
			cacertFile, caCert.Issuer, caCert.Subject)
		if caCert.NotAfter.Before(expirationWarningThreshold) {
			msg := fmt.Sprintf("CA certificate with subject %s will expire on %v (< %d days away)", caCert.Subject, caCert.NotAfter.Format(TimeLayout), expirationDays)
			lg.Printf("WARNING: %s", msg)
			statusch <- ComponentStatusUpdate{
				Component: "cert-status",
				Status:    StatusWarn,
				Msg:       msg,
				TimeStamp: time.Now(),
			}
		}
	}

	return commonName, caCertPool, &clientCert, nil
}
