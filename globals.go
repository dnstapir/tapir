/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

// "github.com/spf13/cobra"
// "github.com/spf13/viper"

type CliFlags struct {
	ShowHdr   bool
	Verbose   bool
	Debug     bool
	UseTLS    bool
	Api       *ApiClient
	PingCount int
	Zone      string
}

var GlobalCF CliFlags
