/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var SloggerCmd = &cobra.Command{
	Use:   "slogger",
	Short: "Prefix command to TAPIR-Slogger, only usable in TAPIR Core, not in TAPIR Edge",
}

var SloggerPopCmd = &cobra.Command{
	Use:   "pop",
	Short: "Prefix command, only usable via sub-commands",
}

var SloggerEdmCmd = &cobra.Command{
	Use:   "edm",
	Short: "Prefix command, only usable via sub-commands",
}

var onlyfails bool

var SloggerPopStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the TAPIR-POP status report from TAPIR-Slogger",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendSloggerCommand(tapir.SloggerCmdPost{
			Command: "status",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)

		if len(resp.PopStatus) == 0 {
			fmt.Printf("No Status reports from any TAPIR-POP received\n")
			os.Exit(0)
		}

		showfails := ""
		if onlyfails {
			showfails = " (only fails)"
		}

		var out []string
		for functionid, ps := range resp.PopStatus {
			fmt.Printf("Status for TAPIR-POP%s: %s\n", showfails, functionid)
			out = []string{"Component|Status|Error msg|NumFailures|LastFailure|LastSuccess"}
			for comp, v := range ps.ComponentStatus {
				if !onlyfails || v.Status == tapir.StatusFail {
					out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%s", comp, tapir.StatusToString[v.Status], v.ErrorMsg, v.NumFails,
						v.LastFail.Format(tapir.TimeLayout), v.LastSuccess.Format(tapir.TimeLayout)))
				}
			}
		}

		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var SloggerEdmStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the TAPIR-EDM status report from TAPIR-Slogger",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendSloggerCommand(tapir.SloggerCmdPost{
			Command: "status",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)

		if len(resp.EdmStatus) == 0 {
			fmt.Printf("No Status reports from any TAPIR-EDM received\n")
			os.Exit(0)
		}

		showfails := ""
		if onlyfails {
			showfails = " (only fails)"
		}

		var out []string
		for functionid, ps := range resp.EdmStatus {
			fmt.Printf("Status for TAPIR-EDM%s: %s\n", showfails, functionid)
			out = []string{"Component|Status|Error msg|NumFailures|LastFailure|LastSuccess"}
			for comp, v := range ps.ComponentStatus {
				if !onlyfails || v.Status == tapir.StatusFail {
					out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%s", comp, tapir.StatusToString[v.Status], v.ErrorMsg, v.NumFails,
						v.LastFail.Format(tapir.TimeLayout), v.LastSuccess.Format(tapir.TimeLayout)))
				}
			}
		}

		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var SloggerPingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send an API ping request to TAPIR-Slogger and present the response",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("ping must have no arguments")
		}

		api, err := SloggerApi()
		if err != nil {
			log.Fatalf("Error: Could not set up API client to TAPIR-SLOGGER: %v", err)
		}

		pr, err := api.SendPing(tapir.GlobalCF.PingCount, false)
		if err != nil {
			log.Fatalf("Error from SendPing: %v", err)
		}

		uptime := time.Now().Sub(pr.BootTime).Round(time.Second)
		if tapir.GlobalCF.Verbose {
			fmt.Printf("%s from %s @ %s (version %s): pings: %d, pongs: %d, uptime: %v time: %s, client: %s\n",
				pr.Msg, pr.Daemon, pr.ServerHost, pr.Version, pr.Pings,
				pr.Pongs, uptime, pr.Time.Format(timelayout), pr.Client)
		} else {
			fmt.Printf("%s: pings: %d, pongs: %d, uptime: %v, time: %s\n",
				pr.Msg, pr.Pings, pr.Pongs, uptime, pr.Time.Format(timelayout))
		}
	},
}

func init() {
	SloggerCmd.AddCommand(SloggerPopCmd, SloggerPingCmd, SloggerEdmCmd)
	SloggerPopCmd.AddCommand(SloggerPopStatusCmd)
	SloggerEdmCmd.AddCommand(SloggerEdmStatusCmd)

	SloggerCmd.PersistentFlags().BoolVarP(&tapir.GlobalCF.ShowHdr, "headers", "H", false, "Show column headers")
	SloggerPopStatusCmd.Flags().BoolVarP(&onlyfails, "onlyfails", "f", false, "Show only components that currently fail")
	SloggerEdmStatusCmd.Flags().BoolVarP(&onlyfails, "onlyfails", "f", false, "Show only components that currently fail")
}

func SloggerApi() (*tapir.ApiClient, error) {
	servername := "tapir-slogger"
	var baseurl, urlkey string
	var err error

	switch tapir.GlobalCF.UseTLS {
	case true:
		urlkey = "cli." + servername + ".tlsurl"
		baseurl = viper.GetString(urlkey)
	case false:
		urlkey = "cli." + servername + ".url"
		baseurl = viper.GetString(urlkey)
	}
	if baseurl == "" {
		return nil, fmt.Errorf("Error: missing config key: %s", urlkey)
	}

	api := &tapir.ApiClient{
		BaseUrl:    baseurl,
		ApiKey:     viper.GetString("cli." + servername + ".apikey"),
		AuthMethod: "X-API-Key",
		Debug:      tapir.GlobalCF.Debug,
		Verbose:    tapir.GlobalCF.Verbose,
	}

	if tapir.GlobalCF.UseTLS { // default = true
		cd := viper.GetString("certs.certdir")
		if cd == "" {
			return nil, fmt.Errorf("Error: missing config key: certs.certdir")
		}
		cert := cd + "/" + tapir.GlobalCF.Certname
		tlsConfig, err := tapir.NewClientConfig(viper.GetString("certs.cacertfile"),
			cert+".key", cert+".crt")
		if err != nil {
			return nil, fmt.Errorf("Error: Could not set up TLS: %v", err)
		}
		tlsConfig.InsecureSkipVerify = true
		err = api.SetupTLS(tlsConfig)
	} else {
		err = api.Setup()
	}
	if err != nil {
		return nil, fmt.Errorf("Error: Could not set up API client to TAPIR-SLOGGER at %s: %v", baseurl, err)
	}
	return api, nil
}

func SendSloggerCommand(data tapir.SloggerCmdPost) tapir.SloggerCmdResponse {
	api, err := SloggerApi()
	if err != nil {
		log.Fatalf("Error: Could not set up API client to TAPIR-SLOGGER: %v", err)
	}

	_, buf, _ := api.RequestNG(http.MethodPost, "/status", data, true)

	var cr tapir.SloggerCmdResponse

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		log.Fatalf("Error from json.Unmarshal: %v\n", err)
	}
	return cr
}
