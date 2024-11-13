/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cmd

import (
	"fmt"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var BumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Instruct TAPIR-POP to bump the SOA serial of the RPZ zone",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "bump",
			Zone:    dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

func init() {
	BumpCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
}


