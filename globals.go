/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

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
