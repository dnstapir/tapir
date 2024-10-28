/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
    "time"

	"github.com/dnstapir/tapir"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

const timelayout = "2006-01-02 15:04:05"

var PopCmd = &cobra.Command{
	Use:   "pop",
	Short: "Prefix command, only usable via sub-commands",
}

var PopMqttCmd = &cobra.Command{
	Use:   "mqtt",
	Short: "Prefix command, only usable via sub-commands",
}

var PopPingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send an API ping request to TAPIR-POP and present the response",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("ping must have no arguments")
		}

		pr, err := tapir.GlobalCF.Api.SendPing(tapir.GlobalCF.PingCount, false)
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

var PopStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get the status of TAPIR-POP",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "status",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)

		if len(resp.TapirFunctionStatus.ComponentStatus) != 0 {
			tfs := resp.TapirFunctionStatus
			fmt.Printf("TAPIR-POP Status. Reported components: %d Total errors (since last start): %d\n", len(tfs.ComponentStatus), tfs.NumFailures)
			var out = []string{"Component|Status|Error msg|# Fails|# Warns|LastFailure|LastSuccess"}
			for k, v := range tfs.ComponentStatus {
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%d|%v|%v", k, tapir.StatusToString[v.Status], v.ErrorMsg, v.NumFails, v.NumWarnings, v.LastFail.Format(tapir.TimeLayout), v.LastSuccess.Format(tapir.TimeLayout)))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		}
	},
}

var PopStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Instruct TAPIR-POP to stop",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "stop",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

var PopMqttStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Instruct TAPIR-POP MQTT Engine to start",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "mqtt-start",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

var PopMqttStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Instruct TAPIR-POP MQTT Engine to stop",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "mqtt-stop",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

var PopMqttRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Instruct TAPIR-POP MQTT Engine to restart",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "mqtt-restart",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

func init() {
	PopCmd.AddCommand(PopStatusCmd, PopStopCmd, PopMqttCmd)
	PopCmd.AddCommand(PopPingCmd)

	PopMqttCmd.AddCommand(PopMqttStartCmd, PopMqttStopCmd, PopMqttRestartCmd)

	PopPingCmd.Flags().IntVarP(&tapir.GlobalCF.PingCount, "count", "c", 0, "#pings to send")
}

func SendCommandCmd(data tapir.CommandPost) tapir.CommandResponse {
	_, buf, _ := tapir.GlobalCF.Api.RequestNG(http.MethodPost, "/command", data, true)

	var cr tapir.CommandResponse

	err := json.Unmarshal(buf, &cr)
	if err != nil {
		log.Fatalf("Error from json.Unmarshal: %v\n", err)
	}
	return cr
}
