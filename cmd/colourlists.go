package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/spf13/cobra"
)

var ColourlistsCmd = &cobra.Command{
	Use:   "colourlists",
	Short: "Return the white/black/greylists from the current data structures",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "colourlists",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
		fmtstring := "%-75s|%-20s|%-20s|%-10s|%-10s\n"

		// print the column headings
		fmt.Printf(fmtstring, "Domain", "Source", "Src Fmt", "Colour", "Flags")
		fmt.Println(strings.Repeat("-", 135)) // A nice ruler over the data rows

		for _, l := range resp.Lists["whitelist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, "-", "white", "-")
			}
		}
		for _, l := range resp.Lists["blacklist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, "-", "black", "-")
			}
		}
		for _, l := range resp.Lists["greylist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, l.SrcFormat, "grey", strconv.Itoa(int(n.TagMask)))
			}
		}
	},
}
