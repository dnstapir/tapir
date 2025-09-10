package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/cobra"
)

// Content of structs based on descriptions at
// https://github.com/dnstapir/nodeman/blob/main/README.md
type enrollReqPayload struct {
	Timestamp time.Time `json:"timestamp"`
	X509CSR   string    `json:"x509_csr"`
	PublicKey jwk.Key   `json:"public_key"`
}

type enrollRespPayload struct {
	X509Certificate   string            `json:"x509_certificate"`
	X509CACertificate string            `json:"x509_ca_certificate"`
	Name              string            `json:"name"`
	MqttBroker        string            `json:"mqtt_broker"`
	AggrecUrl         string            `json:"aggrec_url"`
	MqttTopics        map[string]string `json:"mqtt_topics"`
	TrustedJWKS       jwk.Set           `json:"trusted_jwks"`
}

type renewReqPayload struct {
	Timestamp time.Time `json:"timestamp"`
	X509CSR   string    `json:"x509_csr"`
}

type renewRespPayload struct {
	X509Certificate   string `json:"x509_certificate"`
	X509CACertificate string `json:"x509_ca_certificate"`
}

type enrollCreds struct {
	Name       string
	Key        json.RawMessage
	NodemanURL jsonURL `json:"nodeman_url"`
}

type jsonURL struct {
	url.URL
}

type ConfigData struct { /* For use with config templates below */
	CertdirPath        string
	CaCertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	ConfigTopic        string
	StatusTopic        string
	ObservationsTopic  string
	SignkeyPath        string
	ValidationKeysPath string
	MqttBroker         string
	AggrecUrl          string
}

var EnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll the node into DNSTAPIR",
	Run: func(cmd *cobra.Command, args []string) {
		enroll()
	},
}

var RenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew TLS certs used to secure the MQTT connection",
	Run: func(cmd *cobra.Command, args []string) {
		renew()
	},
}

//go:embed cfgfiles/tapir-edm.toml
var cfgTmplTapirEdm string

//go:embed cfgfiles/tapir-pop.yaml
var cfgTmplTapirPop string

//go:embed cfgfiles/tapir-cli.yaml
var cfgTmplTapirCli string

//go:embed cfgfiles/pop-sources.yaml
var cfgTmplPopSources string

//go:embed cfgfiles/pop-outputs.yaml
var cfgTmplPopOutputs string

//go:embed cfgfiles/pop-policy.yaml
var cfgTmplPopPolicy string

const (
	FLAG_ENROLL_CREDENTIALS   = "enroll-credentials" // #nosec G101 -- only used as flag name in CLI
	FLAG_ENROLL_LOCAL         = "local-response"     // #nosec G101 -- only used as flag name in CLI
	FLAG_ENROLL_CONFDIR       = "confdir"
	FLAG_ENROLL_CERTDIR       = "certdir"
	FLAG_RENEW_DATAKEY        = "renew-datakey"
	FLAG_RENEW_CLIENTKEY      = "renew-clientkey"
	FLAG_RENEW_CACERT_OUT     = "renew-cacert-out"
	FLAG_RENEW_CLIENTCERT_OUT = "renew-clientcert-out"
)

const (
	DIRNAME_DEFAULT_CONFDIR  = "/etc/dnstapir/"
	DIRNAME_DEFAULT_CERTDIR  = "/etc/dnstapir/certs/"
	FILENAME_DATAKEY_PRIV    = "datakey-priv.json"
	FILENAME_TLS_CRT         = "tls.crt"
	FILENAME_TLS_KEY         = "tls.key"
	FILENAME_CA_CRT          = "ca.crt"
	FILENAME_VALKEY_STORE    = "validation-keys.json"
	FILENAME_POP_SOURCES     = "pop-sources.yaml"
	FILENAME_POP_OUTPUTS     = "pop-outputs.yaml"
	FILENAME_POP_POLICY      = "pop-policy.yaml"
	FILENAME_TAPIR_POP       = "tapir-pop.yaml"
	FILENAME_TAPIR_EDM       = "tapir-edm.toml"
	FILENAME_TAPIR_CLI       = "tapir-edm.yaml"
	URL_NODEMAN_API_PATH     = "api/v1/node"
	CONTENT_TYPE_NODEMAN_API = "application/json"
	JWK_KEY_ISS              = "iss"
)

var (
	enrollConfdir       string
	enrollCertdir       string
	enrollCredsFilename string
	enrollRespFilename  string
	renewDatakey        string
	renewClientKey      string
	renewCaCertOut      string
	renewClientCertOut  string
)

func init() {
	EnrollCmd.Flags().StringVarP(&enrollCredsFilename, FLAG_ENROLL_CREDENTIALS, "c", "", "DNSTAPIR enrollment credentials")
	EnrollCmd.Flags().StringVarP(&enrollRespFilename, FLAG_ENROLL_LOCAL, "L", "", "Use a response stored locally")
	EnrollCmd.Flags().StringVarP(&enrollConfdir, FLAG_ENROLL_CONFDIR, "", DIRNAME_DEFAULT_CONFDIR, "Directory for storing configuration files")
	EnrollCmd.Flags().StringVarP(&enrollCertdir, FLAG_ENROLL_CERTDIR, "", DIRNAME_DEFAULT_CERTDIR, "Directory for storing cryptographic material on disk")

	err := EnrollCmd.MarkFlagRequired(FLAG_ENROLL_CREDENTIALS)
	if err != nil {
		panic(err)
	}

	RenewCmd.Flags().StringVarP(&renewDatakey, FLAG_RENEW_DATAKEY, "D", "", "Datakey used to sign the renew request")
	RenewCmd.Flags().StringVarP(&renewClientKey, FLAG_RENEW_CLIENTKEY, "k", "", "Private key for which to receive a certificate for")
	RenewCmd.Flags().StringVarP(&renewCaCertOut, FLAG_RENEW_CACERT_OUT, "C", "", "File to write CA cert from response to")
	RenewCmd.Flags().StringVarP(&renewClientCertOut, FLAG_RENEW_CLIENTCERT_OUT, "c", "", "File to write renewed client cert from response to")

	err = RenewCmd.MarkFlagRequired(FLAG_RENEW_DATAKEY)
	if err != nil {
		panic(err)
	}

	err = RenewCmd.MarkFlagRequired(FLAG_RENEW_CLIENTKEY)
	if err != nil {
		panic(err)
	}

	err = RenewCmd.MarkFlagRequired(FLAG_RENEW_CACERT_OUT)
	if err != nil {
		panic(err)
	}

	err = RenewCmd.MarkFlagRequired(FLAG_RENEW_CLIENTCERT_OUT)
	if err != nil {
		panic(err)
	}
}

func enroll() {
	sourcesFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_POP_SOURCES))
	if err != nil {
		panic(err)
	}
	outputsFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_POP_OUTPUTS))
	if err != nil {
		panic(err)
	}
	policyFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_POP_POLICY))
	if err != nil {
		panic(err)
	}
	tapirPopFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_TAPIR_POP))
	if err != nil {
		panic(err)
	}
	tapirEdmFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_TAPIR_EDM))
	if err != nil {
		panic(err)
	}
	tapirCliFilename, err := filepath.Abs(filepath.Join(enrollConfdir, FILENAME_TAPIR_CLI))
	if err != nil {
		panic(err)
	}
	certdirPath, err := filepath.Abs(enrollCertdir)
	if err != nil {
		panic(err)
	}
	caCertPath, err := filepath.Abs(filepath.Join(enrollCertdir, FILENAME_CA_CRT))
	if err != nil {
		panic(err)
	}
	clientCertPath, err := filepath.Abs(filepath.Join(enrollCertdir, FILENAME_TLS_CRT))
	if err != nil {
		panic(err)
	}
	clientKeyPath, err := filepath.Abs(filepath.Join(enrollCertdir, FILENAME_TLS_KEY))
	if err != nil {
		panic(err)
	}
	validationKeysPath, err := filepath.Abs(filepath.Join(enrollCertdir, FILENAME_VALKEY_STORE))
	if err != nil {
		panic(err)
	}
	signkeyPath, err := filepath.Abs(filepath.Join(enrollCertdir, FILENAME_DATAKEY_PRIV))
	if err != nil {
		panic(err)
	}

	cfg := ConfigData{
		CertdirPath:        certdirPath,
		CaCertPath:         caCertPath,
		ClientCertPath:     clientCertPath,
		ClientKeyPath:      clientKeyPath,
		ValidationKeysPath: validationKeysPath,
		SignkeyPath:        signkeyPath,
		MqttBroker:         "### EDIT add MQTT broker URL",
		AggrecUrl:          "### EDIT add URL for sending aggregated data",
	}

	if !fileExists(enrollConfdir) {
		panic(fmt.Sprintf("Config dir '%s' not found. Aborting...", enrollConfdir))
	}
	if !fileExists(cfg.CertdirPath) {
		panic(fmt.Sprintf("Certdir '%s' not found. Aborting...", cfg.CertdirPath))
	}
	if fileExists(sourcesFilename) {
		panic("Found existing source conf. Aborting...")
	}
	if fileExists(outputsFilename) {
		panic("Found existing output conf. Aborting...")
	}
	if fileExists(policyFilename) {
		panic("Found existing policy conf. Aborting...")
	}
	if fileExists(tapirPopFilename) {
		panic("Found existing POP conf. Aborting...")
	}
	if fileExists(tapirEdmFilename) {
		panic("Found existing EDM conf. Aborting...")
	}
	if fileExists(tapirCliFilename) {
		panic("Found existing EDM conf. Aborting...")
	}
	if fileExists(cfg.ClientCertPath) {
		panic("Found an existing TLS client cert in certdir. Aborting...")
	}
	if fileExists(cfg.CaCertPath) {
		panic("Found an existing CA cert in certdir. Aborting...")
	}
	if fileExists(cfg.ValidationKeysPath) {
		panic("Found existing validation keys in certdir. Aborting...")
	}

	credsFh, err := os.Open(filepath.Clean(enrollCredsFilename))
	if err != nil {
		panic(err)
	}
	defer credsFh.Close()

	creds := enrollCreds{}

	err = json.NewDecoder(credsFh).Decode(&creds)
	if err != nil {
		panic(err)
	}

	if creds.NodemanURL.String() == "" {
		panic("creds file missing nodeman_url")
	}

	if fileExists(cfg.SignkeyPath) {
		fmt.Printf("Using existing data key '%s'\n", cfg.SignkeyPath)
	} else {
		fmt.Printf("Generating new data key '%s'\n", cfg.SignkeyPath)
		_, dataKeyRaw, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		dataKeyJWK, err := jwk.FromRaw(dataKeyRaw)
		if err != nil {
			panic(err)
		}

		err = dataKeyJWK.Set(jwk.KeyIDKey, creds.Name)
		if err != nil {
			panic(err)
		}

		err = dataKeyJWK.Set(jwk.AlgorithmKey, jwa.EdDSA)
		if err != nil {
			panic(err)
		}

		err = dataKeyJWK.Set(JWK_KEY_ISS, creds.NodemanURL.String())
		if err != nil {
			panic(err)
		}

		dataKeyJSON, err := json.Marshal(dataKeyJWK)
		if err != nil {
			panic(err)
		}

		writeToFile(cfg.SignkeyPath, string(dataKeyJSON))
	}

	keyFile, err := os.ReadFile(cfg.SignkeyPath)
	if err != nil {
		panic(err)
	}

	dataKey, err := jwk.ParseKey(keyFile)
	if err != nil {
		panic(err)
	}

	if fileExists(cfg.ClientKeyPath) {
		fmt.Printf("Using existing TLS key '%s'\n", cfg.ClientKeyPath)
	} else {
		fmt.Printf("Generating new TLS key '%s'\n", cfg.ClientKeyPath)

		tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		tlsKeyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
		if err != nil {
			panic(err)
		}

		tlsKeyPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: tlsKeyDER,
		}

		writeToFile(cfg.ClientKeyPath, string(pem.EncodeToMemory(tlsKeyPEM)))
	}

	tlsKey, err := getTlsKey(cfg.ClientKeyPath)
	if err != nil {
		panic(err)
	}

	var body []byte
	if enrollRespFilename != "" {
		fmt.Printf("Using local copy '%s' of previous nodeman response\n", enrollRespFilename)
		body, err = os.ReadFile(filepath.Clean(enrollRespFilename))
		if err != nil {
			panic(err)
		}
	} else {
		csr, err := genCsr(tlsKey, creds.Name)
		if err != nil {
			panic(err)
		}

		enrollmentKey, err := jwk.ParseKey(creds.Key)
		if err != nil {
			panic(err)
		}

		dataKeyPub, err := dataKey.PublicKey()
		if err != nil {
			panic(err)
		}

		payload := enrollReqPayload{
			Timestamp: time.Now(),
			X509CSR:   csr,
			PublicKey: dataKeyPub,
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			panic(err)
		}

		payloadJWS, err := jws.Sign(payloadJSON, jws.WithJSON(), jws.WithKey(dataKey.Algorithm(), dataKey), jws.WithKey(enrollmentKey.Algorithm(), enrollmentKey))
		if err != nil {
			panic(err)
		}

		payloadReader := bytes.NewReader(payloadJWS)

		enrollURL, err := url.JoinPath(creds.NodemanURL.String(), URL_NODEMAN_API_PATH, creds.Name, "enroll")
		if err != nil {
			panic(err)
		}

		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err := client.Post(enrollURL, CONTENT_TYPE_NODEMAN_API, payloadReader) //#nosec G107 -- URL read from a file that the user chooses with CLI args and that is assumed to be from a trusted source
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		if resp.StatusCode != http.StatusOK {
			panic(fmt.Errorf("unexpected status code from enrollment: %d (%s)", resp.StatusCode, body))
		}

		respFilename := fmt.Sprintf("./nodeman-resp-%d.json", time.Now().Unix())
		writeToFile(respFilename, string(body))
	}

	respPayload := enrollRespPayload{
		TrustedJWKS: jwk.NewSet(),
	}
	err = json.Unmarshal(body, &respPayload)
	if err != nil {
		panic(err)
	}

	if respPayload.Name != creds.Name {
		fmt.Println("WARNING, EDGE name mismatch between credentials and response!")
	}

	writeToFile(cfg.ClientCertPath, respPayload.X509Certificate)
	writeToFile(cfg.CaCertPath, respPayload.X509CACertificate)

	trustedKeys, err := json.MarshalIndent(respPayload.TrustedJWKS, "", "  ")
	if err != nil {
		panic(err)
	}
	writeToFile(cfg.ValidationKeysPath, string(trustedKeys))

	var ok bool
	cfg.ConfigTopic, ok = respPayload.MqttTopics["config"]
	if !ok {
		cfg.ConfigTopic = "### EDIT add config topic"
	}
	cfg.StatusTopic, ok = respPayload.MqttTopics["status"]
	if !ok {
		cfg.StatusTopic = "### EDIT add status topic"
	}
	cfg.ObservationsTopic, ok = respPayload.MqttTopics["observations"]
	if !ok {
		cfg.ObservationsTopic = "### EDIT add observations topic"
	}
	if respPayload.MqttBroker != "" {
		cfg.MqttBroker = respPayload.MqttBroker
	}
	if respPayload.AggrecUrl != "" {
		cfg.AggrecUrl = respPayload.AggrecUrl
	}

	tmlSources, err := template.New("sources").Parse(cfgTmplPopSources)
	if err != nil {
		panic(err)
	}

	fhSources, err := os.OpenFile(sourcesFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	defer fhSources.Close()

	err = tmlSources.Execute(fhSources, cfg)
	if err != nil {
		panic(err)
	}

	tmlTapirPop, err := template.New("tapir-pop").Parse(cfgTmplTapirPop)
	if err != nil {
		panic(err)
	}

	fhTapirPop, err := os.OpenFile(tapirPopFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	defer fhTapirPop.Close()

	err = tmlTapirPop.Execute(fhTapirPop, cfg)
	if err != nil {
		panic(err)
	}

	tmlTapirEdm, err := template.New("tapir-edm").Parse(cfgTmplTapirEdm)
	if err != nil {
		panic(err)
	}

	fhTapirEdm, err := os.OpenFile(tapirEdmFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	defer fhTapirEdm.Close()

	err = tmlTapirEdm.Execute(fhTapirEdm, cfg)
	if err != nil {
		panic(err)
	}

	tmlTapirCli, err := template.New("tapir-cli").Parse(cfgTmplTapirCli)
	if err != nil {
		panic(err)
	}

	fhTapirCli, err := os.OpenFile(tapirCliFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	defer fhTapirCli.Close()

	err = tmlTapirCli.Execute(fhTapirCli, cfg)
	if err != nil {
		panic(err)
	}

	writeToFile(outputsFilename, cfgTmplPopOutputs) /* no templating needed right now */
	writeToFile(policyFilename, cfgTmplPopPolicy)   /* no templating needed right now */
}

func renew() {
	if fileExists(renewCaCertOut) {
		fmt.Printf("Will overwrite existing file %s\n", renewCaCertOut)
	}
	if fileExists(renewClientCertOut) {
		fmt.Printf("Will overwrite existing file %s\n", renewCaCertOut)
	}

	keyFile, err := os.ReadFile(renewDatakey) // #nosec G304 -- variable is set by CLI flag only
	if err != nil {
		panic(err)
	}

	dataKey, err := jwk.ParseKey(keyFile)
	if err != nil {
		panic(err)
	}

	value, ok := dataKey.Get(JWK_KEY_ISS)
	if !ok {
		panic(errors.New("datakey missing issuer field containing nodeman url"))
	}

	nodemanUrl, ok := value.(string)
	if !ok {
		panic(errors.New("bad data type for datakey issuer field"))
	}

	renewURL, err := url.JoinPath(nodemanUrl, URL_NODEMAN_API_PATH, dataKey.KeyID(), "renew")
	if err != nil {
		panic(err)
	}

	tlsKey, err := getTlsKey(renewClientKey)
	if err != nil {
		panic(err)
	}

	csr, err := genCsr(tlsKey, dataKey.KeyID())
	if err != nil {
		panic(err)
	}

	requestPayload := renewReqPayload{
		Timestamp: time.Now(),
		X509CSR:   csr,
	}

	payloadJSON, err := json.Marshal(requestPayload)
	if err != nil {
		panic(err)
	}

	payloadJWS, err := jws.Sign(payloadJSON, jws.WithJSON(), jws.WithKey(dataKey.Algorithm(), dataKey))
	if err != nil {
		panic(err)
	}

	payloadReader := bytes.NewReader(payloadJWS)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Post(renewURL, CONTENT_TYPE_NODEMAN_API, payloadReader) // #nosec G107 -- URL read from keyfile that the user chooses with CLI args and that is assumed to be trusted by the user
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("unexpected status code from renewal: %d (%s)", resp.StatusCode, body))
	}

	respPayload := renewRespPayload{}

	err = json.Unmarshal(body, &respPayload)
	if err != nil {
		panic(err)
	}

	writeToFile(renewCaCertOut, respPayload.X509CACertificate)
	writeToFile(renewClientCertOut, respPayload.X509Certificate)
}

func fileExists(filename string) bool {
	fmt.Printf("Checking if file '%s' exists\n", filename)
	_, err := os.Stat(filepath.Clean(filename))

	if errors.Is(err, os.ErrNotExist) {
		return false
	} else if err == nil {
		return true
	}
	panic(err)
}

func writeToFile(filename, contents string) {
	fmt.Printf("Attempting to write to file '%s'\n", filename)
	err := os.WriteFile(filepath.Clean(filename), []byte(contents), 0660)

	if err != nil {
		fh, innerErr := os.CreateTemp("", "tapir-cli-tmp-")

		if innerErr != nil {
			panic(err)
		}
		defer fh.Close()
		fmt.Printf("WARNING, due to an error '%s' a temporary file '%s' will be used instead\n", err, fh.Name())

		_, innerErr = fh.Write([]byte(contents))
		if innerErr != nil {
			panic(err)
		}
	}
}

func (u *jsonURL) UnmarshalJSON(data []byte) error {
	var urlString string

	err := json.Unmarshal(data, &urlString)
	if err != nil {
		return err
	}

	if urlString == "" {
		return errors.New("url has no content")
	}

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return err
	}

	u.URL = *parsedURL

	return nil
}

func getTlsKey(filename string) (*ecdsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key DER data")
	}

	tlsKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key to the desired type")
	}

	return tlsKey, nil
}

func genCsr(key *ecdsa.PrivateKey, name string) (string, error) {
	subject := pkix.Name{
		CommonName: name,
	}

	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Subject:            subject,
			DNSNames:           []string{name},
		},
		key,
	)
	if err != nil {
		return "", err
	}

	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	fmt.Printf("CSR generated successfully\n")

	return string(pem.EncodeToMemory(csrBlock)), nil
}
