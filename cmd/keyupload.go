/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"crypto/sha256"
	"encoding/pem"
	"path/filepath"

	"fmt"
	"log"
	"os"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/cobra"
)

var pubkeyfile string

var KeyUploadCmd = &cobra.Command{
	Use:   "keyupload",
	Short: "Upload a public key to a TAPIR Core",
	Long:  `Upload a public key to a TAPIR Core. The key must be in PEM format.`,
	Run: func(cmd *cobra.Command, args []string) {
		//		if len(args) != 1 {
		//			log.Fatal("keyupload must have exactly one argument: the path to the public key file")
		//		}

		var statusch = make(chan tapir.ComponentStatusUpdate, 10)

		// If any status updates arrive, print them out
		go func() {
			for status := range statusch {
				fmt.Printf("Status update: %+v\n", status)
			}
		}()

		certCN, _, clientCert, err := tapir.FetchTapirClientCert(log.Default(), statusch)
		if err != nil {
			fmt.Printf("Error from FetchTapirClientCert: %v\n", err)
			os.Exit(1)
		}

		meng, err := tapir.NewMqttEngine("keyupload", mqttclientid, tapir.TapirPub, statusch, log.Default()) // pub, no sub
		if err != nil {
			fmt.Printf("Error from NewMqttEngine: %v\n", err)
			os.Exit(1)
		}

		// Start of Selection
		if pubkeyfile == "" {
			fmt.Println("Error: Public key file not specified")
			os.Exit(1)
		}

		pubkeyfile = filepath.Clean(pubkeyfile)
		pubkeyData, err := os.ReadFile(pubkeyfile)
		if err != nil {
			fmt.Printf("Error reading public key file %s: %v\n", pubkeyfile, err)
			os.Exit(1)
		}

		if tapir.GlobalCF.Debug {
			fmt.Printf("Public key loaded from %s\n", pubkeyfile)
			fmt.Printf("Public key:\n%s\n", string(pubkeyData))
		}

		data := tapir.TapirPubKey{
			Pubkey: string(pubkeyData),
		}

		// Create a new struct to send off
		var certChainPEM string
		for _, cert := range clientCert.Certificate {
			certChainPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
		}

		if tapir.GlobalCF.Debug {
			fmt.Printf("Client certificate chain:\n%s\n", certChainPEM)
		}

		// Sign the data using the client certificate's private key and include the cert chain and key ID in the JWS header
		headers := jws.NewHeaders()
		headers.Set(jws.X509CertChainKey, clientCert.Certificate)

		// Compute key ID as SHA-256 hash of the client certificate
		certBytes := clientCert.Leaf.Raw
		hash := sha256.Sum256(certBytes)
		kid := fmt.Sprintf("%x", hash)
		headers.Set(jws.KeyIDKey, kid)

		// Fix the arguments to jws.Sign
		jwsMessage, err := jws.Sign([]byte(data.Pubkey), jws.WithKey(jwa.RS256, clientCert.PrivateKey), jws.WithHeaders(headers))
		if err != nil {
			fmt.Printf("Error signing data: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("JWS Key ID: %s\n", kid)
		fmt.Printf("JWS Message: %s\n", string(jwsMessage))

		msg := tapir.PubKeyUpload{
			JWSMessage:    string(jwsMessage),
			ClientCertPEM: certChainPEM,
		}

		// mqtttopic = viper.GetString("tapir.keyupload.topic")
		mqtttopic, err := tapir.MqttTopic(certCN, "tapir.keyupload.topic")
		if err != nil {
			fmt.Println("Error: tapir.keyupload.topic not specified in config")
			os.Exit(1)
		}
		fmt.Printf("Using DNS TAPIR keyupload MQTT topic: %s\n", mqtttopic)
		//		signkey, err := tapir.FetchMqttSigningKey(mqtttopic, viper.GetString("tapir.config.signingkey"))
		//		if err != nil {
		//			fmt.Printf("Error fetching MQTT signing key: %v", err)
		//		    os.Exit(1)
		//		}
		meng.PubToTopic(mqtttopic, nil, "struct", false) // XXX: Brr. kludge.

		cmnder, outbox, _, err := meng.StartEngine()
		if err != nil {
			fmt.Printf("Error from StartEngine(): %v\n", err)
			os.Exit(1)
		}

		SetupInterruptHandler(cmnder)

		srcname := "foobar" // XXX: Kludge. Should be the EdgeId from the client certificate.
		if srcname == "" {
			fmt.Println("Error: tapir.config.srcname not specified in config")
			os.Exit(1)
		}

		outbox <- tapir.MqttPkgOut{
			Type:    "raw",
			Topic:   mqtttopic,
			RawData: msg,
		}

		fmt.Println("[Waiting 1000 ms to ensure message has been sent]")
		// Here we need to hang around for a while to ensure that the message has time to be sent.
		time.Sleep(1000 * time.Millisecond)
		fmt.Printf("Hopefully the public key upload message has been sent.\n")
	},
}

func init() {
	KeyUploadCmd.Flags().StringVarP(&pubkeyfile, "pubkey", "P", "", "Name of file containing public key to upload")
}
