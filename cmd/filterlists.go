package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/spf13/cobra"
)

var FilterlistsCmd = &cobra.Command{
	Use:   "filterlists",
	Short: "Return the allow/deny/doubtlists from the current data structures",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "filterlists",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
		fmtstring := "%-75s|%-20s|%-20s|%-10s|%-10s\n"

		// print the column headings
		fmt.Printf(fmtstring, "Domain", "Source", "Src Fmt", "Filter", "Flags")
		fmt.Println(strings.Repeat("-", 135)) // A nice ruler over the data rows

		for _, l := range resp.Lists["allowlist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, "-", "allow", "-")
			}
		}
		for _, l := range resp.Lists["denylist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, "-", "deny", "-")
			}
		}
		for _, l := range resp.Lists["doubtlist"] {
			for _, n := range l.Names {
				fmt.Printf(fmtstring, n.Name, l.Name, l.SrcFormat, "doubt", strconv.Itoa(int(n.TagMask)))
			}
		}
	},
}
