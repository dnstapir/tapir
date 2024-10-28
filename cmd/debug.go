/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
    "strings"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/ryanuber/columnize"

	//	"github.com/ryanuber/columnize"
	"github.com/miekg/dns"
	//"github.com/santhosh-tekuri/jsonschema/v2"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
)

var DebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Prefix command to various debug tools; do not use in production",
}

var debugZoneDataCmd = &cobra.Command{
	Use:   "zonedata",
	Short: "Return the ZoneData struct for the specified zone from server",
	Long: `Return the ZoneData struct from server
 (mostly useful with -d JSON prettyprinter).`,
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "zonedata",
			Zone:    dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		//		zd := resp.ZoneData

		fmt.Printf("Received %d bytes of data\n", len(resp.Msg))
		//		fmt.Printf("Zone %s: RRs: %d Owners: %d\n", tapir.GlobalCF.Zone,
		//			len(zd.RRs), len(zd.Owners))
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var debugColourlistsCmd = &cobra.Command{
	Use:   "colourlists",
	Short: "Return the white/black/greylists from the current data structures",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "colourlists",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
        fmtstring := "%-35s|%-20s|%-10s|%-10s\n"

		//		fmt.Printf("Received %d bytes of data\n", len(resp.Msg))

        // print the column headings
        fmt.Printf(fmtstring, "Domain", "Source", "Src Fmt", "Colour")
        fmt.Println(strings.Repeat("-", 78)) // A nice ruler over the data rows

		for _, l := range resp.Lists["whitelist"] {
            for _, n := range l.Names {
                fmt.Printf(fmtstring, n.Name, l.Name, "-", "white")
            }
		}
		for _, l := range resp.Lists["blacklist"] {
            for _, n := range l.Names {
                fmt.Printf(fmtstring, n.Name, l.Name, "-", "black")
            }
		}
		for _, l := range resp.Lists["greylist"] {
            for _, n := range l.Names {
                fmt.Printf(fmtstring, n.Name, l.Name, l.SrcFormat, "grey")
            }
		}
	},
}

var debugGenRpzCmd = &cobra.Command{
	Use:   "genrpz",
	Short: "Return the white/black/greylists from the current data structures",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "gen-output",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("Received %d bytes of data\n", len(resp.Msg))

		fmt.Printf("black count=%d: %v\n", resp.BlacklistedNames)
		fmt.Printf("grey count=%d: %v\n", resp.GreylistedNames)
		//	    	fmt.Printf("count=%d: %v\n", res.RpzOutput)
		for _, tn := range resp.RpzOutput {
			fmt.Printf("%s\n", (*tn.RR).String())
		}
	},
}

var debugMqttStatsCmd = &cobra.Command{
	Use:   "mqtt-stats",
	Short: "Return the MQTT stats counters from the MQTT Engine",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "mqtt-stats",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}

		var out = []string{"MQTT Topic|Msgs|Last MQTT Message|Time since last msg"}
		for topic, count := range resp.MqttStats.MsgCounters {
			t := resp.MqttStats.MsgTimeStamps[topic]
			out = append(out, fmt.Sprintf("%s|%d|%s|%v\n", topic, count, t.Format(timelayout), time.Since(t).Round(time.Second)))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var debugReaperStatsCmd = &cobra.Command{
	Use:   "reaper-stats",
	Short: "Return the reaper status for all known greylists",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendDebugCmd(tapir.DebugPost{
			Command: "reaper-stats",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}

		for greylist, data := range resp.ReaperStats {
			if len(data) == 0 {
				fmt.Printf("No reaper data for greylist %s\n", greylist)
				continue
			}
			fmt.Printf("From greylist %s at the following times these names will be deleted:\n", greylist)
			out := []string{"Time|Count|Names"}
			for t, d := range data {
				out = append(out, fmt.Sprintf("%s|%d|%v", t.Format(timelayout), len(d), d))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		}
	},
}

var popcomponent, popstatus string

var debugUpdatePopStatusCmd = &cobra.Command{
	Use:   "update-pop-status",
	Short: "Update the status of a TAPIR-POP component, to trigger a status update over MQTT",
	Run: func(cmd *cobra.Command, args []string) {
		switch popstatus {
		case "ok", "warn", "fail":
		default:
			fmt.Printf("Invalid status: %s\n", popstatus)
			os.Exit(1)
		}

		resp := SendDebugCmd(tapir.DebugPost{
			Command:   "send-status",
			Component: popcomponent,
			Status:    tapir.StringToStatus[popstatus],
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var zonefile string

var debugSyncZoneCmd = &cobra.Command{
	Use:   "synczone",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("synczone called")

		if tapir.GlobalCF.Zone == "" {
			fmt.Printf("Zone name not specified.\n")
			os.Exit(1)
		}

		if zonefile == "" {
			fmt.Printf("Zone file not specified.\n")
			os.Exit(1)
		}

		zd := tapir.ZoneData{
			ZoneType: 3, // zonetype=3 keeps RRs in a []OwnerData, with an OwnerIndex map[string]int to locate stuff
			ZoneName: tapir.GlobalCF.Zone,
			Logger:   log.Default(),
		}

		_, err := zd.ReadZoneFile(zonefile)
		if err != nil {
			log.Fatalf("ReloadAuthZones: Error from ReadZoneFile(%s): %v", zonefile, err)
		}

		// XXX: This will be wrong for zonetype=3 (which we're using)
		fmt.Printf("----- zd.BodyRRs: ----\n")
		tapir.PrintRRs(zd.BodyRRs)
		fmt.Printf("----- zd.RRs (pre-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
		zd.Sync()
		fmt.Printf("----- zd.RRs (post-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
		zd.Sync()
		fmt.Printf("----- zd.RRs (post-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
		fmt.Printf("----- zd.BodyRRs: ----\n")
		tapir.PrintRRs(zd.BodyRRs)
	},
}

var Listname string

var debugGreylistStatusCmd = &cobra.Command{
	Use:   "greylist-status",
	Short: "Return the greylist status for all greylists",
	Run: func(cmd *cobra.Command, args []string) {
		status, buf, err := tapir.GlobalCF.Api.RequestNG(http.MethodPost, "/bootstrap", tapir.BootstrapPost{
			Command: "greylist-status",
		}, false)
		if err != nil {
			fmt.Printf("Error from RequestNG: %v\n", err)
			return
		}

		if status != http.StatusOK {
			fmt.Printf("HTTP Error: %s\n", buf)
			return
		}
		var br tapir.BootstrapResponse
		err = json.Unmarshal(buf, &br)
		if err != nil {
			fmt.Printf("Error decoding bootstrap response as a tapir.BootstrapResponse: %v. Giving up.\n", err)
			return
		}
		if br.Error {
			fmt.Printf("Bootstrap Error: %s\n", br.ErrorMsg)
		}
		if len(br.Msg) != 0 {
			fmt.Printf("Bootstrap response: %s\n", br.Msg)
		}
		out := []string{"Server|Uptime|Topic|Last Msg|Time since last msg"}

		// for topic, count := range br.MsgCounters {
		//		out = append(out, fmt.Sprintf("%s|%v|%v|%v", topic, count, br.MsgTimeStamps[topic].Format(time.RFC3339), time.Now().Sub(br.MsgTimeStamps[topic])))
		// }

		for topic, topicdata := range br.TopicData {
			// out = append(out, fmt.Sprintf("%s|%v|%s|%s|%s|%d|%s|%d|%s", server, uptime, name, src.Name, topic, topicdata.PubMsgs, topicdata.LatestPub.Format(time.RFC3339), topicdata.SubMsgs, topicdata.LatestSub.Format(time.RFC3339)))
			out = append(out, fmt.Sprintf("%s|%d|%s|%d|%s", topic, topicdata.PubMsgs, topicdata.LatestPub.Format(time.RFC3339), topicdata.SubMsgs, topicdata.LatestSub.Format(time.RFC3339)))
		}

		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var debugGenerateSchemaCmd = &cobra.Command{
	Use:   "generate-schema",
	Short: "Experimental: Generate the JSON schema for the current data structures",
	Run: func(cmd *cobra.Command, args []string) {

		reflector := &jsonschema.Reflector{
			DoNotReference: true,
		}
		schema := reflector.Reflect(&tapir.WBGlist{}) // WBGlist is only used as a example.
		schemaJson, err := schema.MarshalJSON()
		if err != nil {
			fmt.Printf("Error marshalling schema: %v\n", err)
			os.Exit(1)
		}
		var prettyJSON bytes.Buffer

		// XXX: This doesn't work. It isn't necessary that the response is JSON.
		err = json.Indent(&prettyJSON, schemaJson, "", "  ")
		if err != nil {
			fmt.Printf("Error indenting schema: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v\n", string(prettyJSON.Bytes()))
	},
}

var debugImportGreylistCmd = &cobra.Command{
	Use:   "import-greylist",
	Short: "Import the current data for the named greylist from the TEM bootstrap server",
	Run: func(cmd *cobra.Command, args []string) {

		if Listname == "" {
			fmt.Printf("No greylist name specified, using 'dns-tapir'\n")
			Listname = "dns-tapir"
		}

		status, buf, err := tapir.GlobalCF.Api.RequestNG(http.MethodPost, "/bootstrap", tapir.BootstrapPost{
			Command:  "export-greylist",
			ListName: Listname,
			Encoding: "gob",
		}, false)
		if err != nil {
			fmt.Printf("Error from RequestNG: %v\n", err)
			return
		}

		if status != http.StatusOK {
			fmt.Printf("HTTP Error: %s\n", buf)
			return
		}
		//		if resp.Error {
		//			fmt.Printf("Error: %s\n", resp.ErrorMsg)
		//			return
		//		}

		var greylist tapir.WBGlist
		decoder := gob.NewDecoder(bytes.NewReader(buf))
		err = decoder.Decode(&greylist)
		if err != nil {
			// fmt.Printf("Error decoding greylist data: %v\n", err)
			// If decoding the gob failed, perhaps we received a tapir.CommandResponse instead?
			var br tapir.BootstrapResponse
			err = json.Unmarshal(buf, &br)
			if err != nil {
				fmt.Printf("Error decoding response either as a GOB blob or as a tapir.CommandResponse: %v. Giving up.\n", err)
				return
			}
			if br.Error {
				fmt.Printf("Command Error: %s\n", br.ErrorMsg)
			}
			if len(br.Msg) != 0 {
				fmt.Printf("Command response: %s\n", br.Msg)
			}
			return
		}

		// fmt.Printf("%v\n", greylist)
		fmt.Printf("Names present in greylist %s:", Listname)
		if len(greylist.Names) == 0 {
			fmt.Printf(" None\n")
		} else {
			fmt.Printf("\n")
			out := []string{"Name|Time added|TTL|Tags"}
			for _, n := range greylist.Names {
				ttl := n.TTL - time.Now().Sub(n.TimeAdded).Round(time.Second)
				out = append(out, fmt.Sprintf("%s|%v|%v|%v", n.Name, n.TimeAdded.Format(tapir.TimeLayout), ttl, n.TagMask))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		}

		fmt.Printf("ReaperData present in greylist %s:", Listname)
		if len(greylist.ReaperData) == 0 {
			fmt.Printf(" None\n")
		} else {
			fmt.Printf("\n")
			out := []string{"Time|Count|Names"}
			for t, d := range greylist.ReaperData {
				var names []string
				for n := range d {
					names = append(names, n)
				}
				out = append(out, fmt.Sprintf("%s|%d|%v", t.Format(timelayout), len(d), names))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		}
	},
}

func init() {
	DebugCmd.AddCommand(debugSyncZoneCmd, debugZoneDataCmd, debugColourlistsCmd, debugGenRpzCmd)
	DebugCmd.AddCommand(debugMqttStatsCmd, debugReaperStatsCmd)
	DebugCmd.AddCommand(debugImportGreylistCmd, debugGreylistStatusCmd)
	DebugCmd.AddCommand(debugGenerateSchemaCmd, debugUpdatePopStatusCmd)

	debugUpdatePopStatusCmd.Flags().StringVarP(&popcomponent, "component", "c", "", "Component name")
	debugUpdatePopStatusCmd.Flags().StringVarP(&popstatus, "status", "s", "", "Component status (ok, warn, fail)")

	debugImportGreylistCmd.Flags().StringVarP(&Listname, "list", "l", "", "Greylist name")
	debugSyncZoneCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
	debugZoneDataCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
	debugSyncZoneCmd.Flags().StringVarP(&zonefile, "file", "f", "", "Zone file")
}

type DebugResponse struct {
	Msg      string
	Data     interface{}
	Error    bool
	ErrorMsg string
}

func SendDebugCmd(data tapir.DebugPost) tapir.DebugResponse {
	_, buf, _ := tapir.GlobalCF.Api.RequestNG(http.MethodPost, "/debug", data, true)

	var dr tapir.DebugResponse

	var pretty bytes.Buffer
	err := json.Indent(&pretty, buf, "", "   ")
	if err != nil {
		fmt.Printf("JSON parse error: %v", err)
	}
	//	fmt.Printf("Received %d bytes of data: %v\n", len(buf), pretty.String())
	//	os.Exit(1)

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("Error from json.Unmarshal: %v\n", err)
	}
	return dr
}
