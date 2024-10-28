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
    // TODO cleaner solution:
    // Moved "certname" from slogger.go here so it can know what cert to look
    // for. "certname" was previously declared globally in "root.go", but since
    // the move to the tapir lib, slogger.go no longer sees that variable.
    Certname  string
}

var GlobalCF CliFlags
