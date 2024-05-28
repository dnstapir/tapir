/*
 * Johan Stenstam, johani@johani.org
 */
package tapir

// Client side API client calls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"

	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type ApiClient struct {
	BaseUrl    string
	AuthMethod string
	ApiKey     string
	Timeout    int
	ClientName string // ClientName is used to figure out which client cert to use for TLS setup.
	UseTLS     bool
	Verbose    bool
	Debug      bool
	HttpClient *http.Client
}

func (api *ApiClient) Setup() error {
	var client *http.Client
	var path string

	if api.Timeout > 20 {
		api.Timeout = 20
	}

	api.UseTLS = false
	api.Verbose = GlobalCF.Verbose
	api.Debug = GlobalCF.Debug

	var protocol = "http"

	if api.BaseUrl == "" {
		return fmt.Errorf("baseUrl not defined. Abort")
	}
	if api.Debug {
		log.Printf("api.Setup(): Using baseurl \"%s\"\n", api.BaseUrl)
	}

	// if the service string contains either https:// or http:// then that
	// will override the usetls parameter.
	if strings.HasPrefix(strings.ToLower(api.BaseUrl), "https://") {
		api.BaseUrl = api.BaseUrl[8:]
	} else if strings.HasPrefix(strings.ToLower(api.BaseUrl), "http://") {
		api.BaseUrl = api.BaseUrl[7:]
	}

	ip, port, err := net.SplitHostPort(api.BaseUrl)
	if err != nil {
		return fmt.Errorf("api.Setup(): Error from SplitHostPort: %s. Abort", err)
	}

	if strings.Contains(port, "/") {
		portparts := strings.Split(port, "/")
		port = portparts[0]
		path = "/" + strings.Join(portparts[1:], "/")
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("api.Setup(): Illegal address specification: %s. Abort", ip)
	}

	api.BaseUrl = fmt.Sprintf("%s://%s:%s%s", protocol, addr.String(), port, path)

	if api.Debug {
		log.Printf("NAC: Debug: ip: %s port: %s path: '%s'. BaseURL: %s\n",
			ip, port, path, api.BaseUrl)
	}

	if api.UseTLS {
		return fmt.Errorf("api.Setup(): Use api.SetupTls() for setup of a TLS client")
	}

	client = &http.Client{
		Timeout: time.Duration(api.Timeout) * time.Second,
		// CheckRedirect: redirectPolicyFunc,
	}

	if api.AuthMethod != "Authorization" && api.AuthMethod != "X-API-Key" && api.AuthMethod != "none" {
		return fmt.Errorf("api.Setup(): unknown http auth method: %s", api.AuthMethod)
	}

	api.HttpClient = client
	return nil
}

// This is a version of the ApiClient constructor that should replace NewTlsApiClient()
func (api *ApiClient) SetupTLS(tlsConfig *tls.Config) error {
	var client *http.Client
	var path string

	api.UseTLS = false
	api.Verbose = GlobalCF.Verbose
	api.Debug = GlobalCF.Debug

	var protocol = "https"

	if api.BaseUrl == "" {
		return fmt.Errorf("baseUrl not defined. Abort")
	}
	if api.Debug {
		log.Printf("api.SetupTLS: Using baseurl \"%s\"\n", api.BaseUrl)
	}

	// Strip off https:// or http://
	if strings.HasPrefix(strings.ToLower(api.BaseUrl), "https://") {
		api.BaseUrl = api.BaseUrl[8:]
	} else if strings.HasPrefix(strings.ToLower(api.BaseUrl), "http://") {
		api.BaseUrl = api.BaseUrl[7:]
	}

	ip, port, err := net.SplitHostPort(api.BaseUrl)
	if err != nil {
		return fmt.Errorf("api.SetupTLS: Error from SplitHostPort: %s. Abort", err)
	}

	if strings.Contains(port, "/") {
		portparts := strings.Split(port, "/")
		port = portparts[0]
		path = "/" + strings.Join(portparts[1:], "/")
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("api.SetupTLS: Illegal address specification: %s. Abort", ip)
	}

	api.BaseUrl = fmt.Sprintf("%s://%s:%s%s", protocol, addr.String(), port, path)

	if api.Debug {
		log.Printf("api.SetupTLS: Debug: ip: %s port: %s path: '%s'. BaseURL: %s\n",
			ip, port, path, api.BaseUrl)
	}

	cacert := viper.GetString("certs.cacertfile")
	if cacert == "" {
		return fmt.Errorf("cannot use TLS without a CA cert, see config key certs.cacertfile")
	}
	_, err = os.ReadFile(cacert)
	if err != nil {
		return fmt.Errorf("error reading CA file '%s': %v", cacert, err)
	}
	//	roots := x509.NewCertPool()
	//	ok := roots.AppendCertsFromPEM(caCertPEM)
	//	if !ok {
	//		log.Printf("Error parsing root cert: %v\n", err)
	//	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	if api.AuthMethod != "Authorization" && api.AuthMethod != "X-API-Key" && api.AuthMethod != "none" {
		log.Fatalf("api.SetupTLS: unknown http auth method: %s", api.AuthMethod)
	}

	api.HttpClient = client
	return nil
}

func (api *ApiClient) UrlReport(method, endpoint string, data []byte) {
	if !api.Debug {
		return
	}

	if api.UseTLS {
		fmt.Printf("API%s: apiurl: %s (using TLS)\n", method, api.BaseUrl+endpoint)
	} else {
		fmt.Printf("API%s: apiurl: %s\n", method, api.BaseUrl+endpoint)
	}

	if (method == http.MethodPost) || (method == http.MethodPut) {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, data, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("API%s: posting %d bytes of data: %s\n", method, len(data), prettyJSON.String())
	}
}

// this function will die when we kill the individual request functions.
func (api *ApiClient) AddAuthHeader(req *http.Request) {
	req.Header.Add("Content-Type", "application/json")
	if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.ApiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.ApiKey))
		// } else if api.AuthMethod == "none" {
		// do not add any authentication header at all
	}
}

func (api *ApiClient) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	bytebuf := new(bytes.Buffer)
	err := json.NewEncoder(bytebuf).Encode(data)
	if err != nil {
		fmt.Printf("api.RequestNG: Error from json.NewEncoder: %v\n", err)
		if dieOnError {
			os.Exit(1)
		}
	}

	api.UrlReport(method, endpoint, bytebuf.Bytes())

	if api.Debug {
		fmt.Printf("api.RequestNG: %s %s dieOnError: %v\n", method, endpoint, dieOnError)
	}

	req, err := http.NewRequest(method, api.BaseUrl+endpoint, bytebuf)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create new HTTP request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.ApiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.ApiKey))
		// } else if api.AuthMethod == "none" {
		// do not add any authentication header at all
	}
	resp, err := api.HttpClient.Do(req)

	if err != nil {
		if api.Debug {
			fmt.Printf("api.RequestNG: %s %s dieOnError: %v err: %v\n", method, endpoint, dieOnError, err)
		}

		var msg string
		if strings.Contains(err.Error(), "connection refused") {
			msg = "Connection refused. Server process probably not running."
		} else {
			msg = fmt.Sprintf("Error from API request %s: %v", method, err)
		}
		if dieOnError {
			fmt.Printf("%s\n", msg)
			os.Exit(1)
		} else {
			return 501, nil, err
		}
	}

	status := resp.StatusCode
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("RequestNG: io.ReadAll(): %s", err)
		return http.StatusInternalServerError, nil, fmt.Errorf("RequestNG: io.ReadAll: %w", err)
	}
	defer resp.Body.Close()

	if api.Debug {
		fmt.Printf("Status from %s: %d\n", method, status)
		if status != http.StatusOK {
			fmt.Printf("api.RequestNG: Status is != http.StatusOK: returned bytes: %s\n", string(buf))
		}
	}

	if api.Debug {
		var prettyJSON bytes.Buffer

		// XXX: This doesn't work. It isn't necessary that the response is JSON.
		err := json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			// XXX: Let's assume that the response isn't JSON.
			// log.Println("JSON parse error: ", err)
		} else {
			fmt.Printf("API%s: received %d bytes of response data: %s\n", method, len(buf), string(buf))
		}
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}
