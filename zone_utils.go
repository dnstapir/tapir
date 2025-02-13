/*
 * Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) Refresh(upstream string) (bool, error) {
	verbose := true

	do_transfer, current_serial, upstream_serial, err := zd.DoTransfer(upstream)
	if err != nil {
		log.Printf("Error from DoZoneTransfer(%s): %v", zd.ZoneName, err)
		return false, err
	}

	if do_transfer {
		log.Printf("Refresher: %s: upstream serial has increased: %d-->%d (refresh: %d)",
			zd.ZoneName, current_serial, upstream_serial, zd.SOA.Refresh)
		err = zd.FetchFromUpstream(upstream, current_serial, verbose)
		if err != nil {
			log.Printf("Error from FetchFromUpstream(%s, %s): %v", zd.ZoneName, upstream, err)
			return false, err
		}
		return true, nil // zone updated, no error
	}
	log.Printf("Refresher: %s: upstream serial is unchanged: %d (refresh: %d)",
		zd.ZoneName, current_serial, zd.SOA.Refresh)

	return false, nil
}

func (zd *ZoneData) DoTransfer(upstream string) (bool, uint32, uint32, error) {
	var upstream_serial uint32
	var current_serial uint32 = 0

	if zd == nil {
		panic("DoTransfer: zd == nil")
	}

	// log.Printf("%s: known zone, current incoming serial %d", zd.ZoneName, zd.IncomingSerial)
	m := new(dns.Msg)
	m.SetQuestion(zd.ZoneName, dns.TypeSOA)

	r, err := dns.Exchange(m, upstream)
	if err != nil {
		log.Printf("Error from dns.Exchange(%s, SOA): %v", zd.ZoneName, err)
		return false, zd.IncomingSerial, 0, err
	}

	rcode := r.MsgHdr.Rcode
	switch rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameError:
		return false, current_serial, 0, nil // never mind
	case dns.RcodeSuccess:
		if soa, ok := r.Answer[0].(*dns.SOA); ok {
			// log.Printf("UpstreamSOA: %v", soa.String())
			if soa.Serial <= zd.IncomingSerial {
				// log.Printf("New upstream serial for %s (%d) is <= current serial (%d)",
				// 	zd.ZoneName, soa.Serial, current_serial)
				return false, zd.IncomingSerial, soa.Serial, nil
			}
			// log.Printf("New upstream serial for %s (%d) is > current serial (%d)",
			// 	zd.ZoneName, soa.Serial, current_serial)
			return true, zd.IncomingSerial, soa.Serial, nil
		}
	default:
	}

	return false, zd.IncomingSerial, upstream_serial, nil
}

func (zd *ZoneData) FetchFromUpstream(upstream string, current_serial uint32, verbose bool) error {
	log.Printf("Transferring zone %s via AXFR from %s\n", zd.ZoneName, upstream)

	zonedata := ZoneData{
		ZoneName: zd.ZoneName,
		ZoneType: zd.ZoneType,
		//		RRKeepFunc:  zd.RRKeepFunc,
		RRParseFunc: zd.RRParseFunc,
		//		RpzData:     zd.RpzData,
		Logger:  zd.Logger,
		Verbose: zd.Verbose,
	}

	_, err := zonedata.ZoneTransferIn(upstream, current_serial, "axfr")
	if err != nil {
		log.Printf("Error from ZoneTransfer(%s): %v", zd.ZoneName, err)
		return err
	}
	log.Printf("FetchFromUpstream: %s has %d apex RRs +  %d RRs",
		zd.ZoneName, zonedata.ApexLen, len(zonedata.BodyRRs))

	zonedata.Sync()

	if viper.GetBool("service.debug") {
		filedir := viper.GetString("log.filedir")
		zonedata.WriteFile(fmt.Sprintf("%s/%s.tapir-em", filedir, zd.ZoneName), log.Default())
	}

	zd.RRs = zonedata.RRs
	zd.Owners = zonedata.Owners
	zd.OwnerIndex = zonedata.OwnerIndex
	zd.BodyRRs = zonedata.BodyRRs
	zd.SOA = zonedata.SOA
	zd.IncomingSerial = zd.SOA.Serial
	zd.NSrrs = zonedata.NSrrs
	zd.ApexLen = zonedata.ApexLen
	zd.XfrType = zonedata.XfrType
	zd.ZoneType = zonedata.ZoneType
	zd.Data = zonedata.Data
	//	zd.RpzData = zonedata.RpzData

	return nil
}

func (zd *ZoneData) Sync() error {
	log.Printf("zd.Sync(): pre sync: there are %d RRs in BodyRRs and %d RRs in RRs",
		len(zd.BodyRRs), len(zd.RRs))
	rrs := []dns.RR{dns.RR(&zd.SOA)}
	rrs = append(rrs, zd.NSrrs...)

	switch zd.ZoneType {
	case RpzZone:
	case SliceZone:
		for _, odmap := range zd.Data {
			for _, rrl := range odmap.RRtypes {
				rrs = append(rrs, rrl.RRs...)
			}
		}
	default:
		//		rrs = append(rrs, zd.BodyRRs...)
	}

	zd.RRs = rrs
	return nil
}

func (zd *ZoneData) PrintOwners() {
	switch zd.ZoneType {
	case SliceZone:
		zd.Logger.Printf("owner name\tindex\n")
		for i, v := range zd.Owners {
			rrtypes := []string{}
			for t := range v.RRtypes {
				rrtypes = append(rrtypes, dns.TypeToString[t])
			}
			zd.Logger.Printf("%d\t%s\t%s\n", i, v.Name, strings.Join(rrtypes, ", "))
		}
		for k, v := range zd.OwnerIndex {
			zd.Logger.Printf("%s\t%d\n", k, v)
		}
	default:
		zd.Logger.Printf("Sorry, only zonetype=3 for now")
	}
}
