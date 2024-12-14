/*
 * Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cmd

import (
	"log"

	"github.com/dnstapir/tapir"
	"github.com/spf13/cobra"
)

var ApiCmd = &cobra.Command{
	Use:   "api",
	Short: "request a TAPIR-POP api summary",
	Long:  `Query TAPIR-POP for the provided API endpoints and print that out in a (hopefully) comprehensible fashion.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("api must have no arguments")
		}
		tapir.GlobalCF.Api.ShowApi()
	},
}
