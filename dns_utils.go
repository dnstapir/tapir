/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	// "github.com/DmitriyVTitov/size"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const (
	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits
	TimeLayout = "2006-01-02 15:04:05"
)

// TODO: Add support for TSIG zone transfers.

func (zd *ZoneData) ZoneTransferIn(upstream string, serial uint32, ttype string) (uint32, error) {
	if upstream == "" {
		log.Fatalf("ZoneTransfer: upstream not set")
	}

	msg := new(dns.Msg)
	if ttype == "ixfr" {
		// msg.SetIxfr(zone, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zd.ZoneName, serial, "", "")
	} else {
		msg.SetAxfr(zd.ZoneName)
	}

	switch zd.ZoneType {
	case MapZone, SliceZone, RpzZone:
		zd.Data = make(map[string]OwnerData, 30)
	}

	log.Printf("ZoneTransferIn: ZoneType: %s", ZoneTypeToString[zd.ZoneType])

	transfer := new(dns.Transfer)
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		zd.Logger.Printf("Error from transfer.In: %v\n", err)
		return 0, err
	}

	count := 0
	var first_soa *dns.SOA
	for envelope := range answerChan {
		if envelope.Error != nil {
			zd.Logger.Printf("ZoneTransferIn: zone %s error: %v", zd.ZoneName, envelope.Error)
			break
		}

		// log.Printf("ZoneTransferIn: size of env: %d RRs", len(envelope.RR)) // ~5-600 RRs
		for _, rr := range envelope.RR {
			count++
			zd.RRSortFunc(rr, first_soa)
		}
		if zd.Verbose && (count%100000 == 0) {
			//		   zd.Logger.Printf("%d RRs transferred (total %d RRs kept)",
			//				len(envelope.RR), len(zd.BodyRRs)+zd.ApexLen)
			zd.Logger.Printf("%d RRs transferred", len(envelope.RR))
		}
	}

	zd.Logger.Printf("ZoneTransferIn: %s: dropped %d RRs (filter), kept %d apex RRs",
		zd.ZoneName, zd.DroppedRRs, zd.ApexLen)

	zd.Logger.Printf("*** Zone %s transferred from upstream %s. No errors.", zd.ZoneName, upstream)

	zd.ComputeIndices()

	//	if IsIxfr(zd.RRs) {
	//		zd.XfrType = "ixfr"
	//	} else {
	zd.XfrType = "axfr"
	//	}
	if len(zd.RRs) == 0 {
		return 0, nil
	}

	return first_soa.Serial, nil
}

func (zd *ZoneData) ReadZoneFile(filename string) (uint32, error) {
	zd.Logger.Printf("ReadZoneFile: zone: %s filename: %s", zd.ZoneName, filename)

	f, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("ReadZoneFile: Error: failed to read %s: %v", filename, err)
	}

	return zd.ReadZone(bufio.NewReader(f))
}

func (zd *ZoneData) ReadZoneString(s string) (uint32, error) {
	zd.Logger.Printf("ReadZoneString: zone: %s", zd.ZoneName)

	return zd.ReadZone(strings.NewReader(s))
}

func (zd *ZoneData) ReadZone(r io.Reader) (uint32, error) {
	switch zd.ZoneType {
	case MapZone, SliceZone, RpzZone:
		// zd.Data = make(map[string]map[uint16][]dns.RR, 30)
		zd.Data = make(map[string]OwnerData, 30)
	}

	var first_soa *dns.SOA
	zp := dns.NewZoneParser(r, "", "")
	zp.SetIncludeAllowed(true)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		zd.RRSortFunc(rr, first_soa)
	}

	if err := zp.Err(); err != nil {
		zd.Logger.Printf("ReadZoneFile: Error from ZoneParser(%s): %v", zd.ZoneName, err)
		return zd.SOA.Serial, fmt.Errorf("error from ZoneParser: %v", err)
	}
	zd.Logger.Printf("*** Zone %s read from file. No errors.", zd.ZoneName)

	zd.ComputeIndices() // for zonetype 3, otherwise no-op

	zd.XfrType = "axfr" // XXX: technically not true, but the distinction is between complete zone and "diff"

	zd.Logger.Printf("ReadZoneFile: %s: dropped %d RRs (filter), kept %d apex RRs",
		zd.ZoneName, zd.DroppedRRs, zd.ApexLen)

	return zd.SOA.Serial, nil
}

func (zd *ZoneData) RRSortFunc(rr dns.RR, first_soa *dns.SOA) {
	zd.KeptRRs++

	if zd.RRParseFunc != nil && !zd.RRParseFunc(&rr, zd) {
		zd.DroppedRRs++
		return
	}

	owner := rr.Header().Name
	rrtype := rr.Header().Rrtype

	if zd.Debug {
		zd.Logger.Printf("RRSortFunc: owner=%s rrtype=%s zonetype: %s", owner, dns.TypeToString[rrtype], ZoneTypeToString[zd.ZoneType])
	}

	var odmap OwnerData
	switch zd.ZoneType {
	case SliceZone, RpzZone:
		fallthrough // store slicezones as mapzones during inbound transfer, sort afterwards into slice
	case MapZone:
		odmap = zd.Data[owner]
		if odmap.RRtypes == nil {
			odmap.Name = owner
			odmap.RRtypes = map[uint16]RRset{}
		}
	}

	var tmp RRset

	switch v := rr.(type) {
	case *dns.SOA:
		if first_soa == nil {
			first_soa = v
			zd.SOA = *first_soa
			zd.ApexLen++
		}
		tmp = odmap.RRtypes[rrtype]
		tmp.RRs = append(tmp.RRs, rr)
		odmap.RRtypes[rrtype] = tmp
	case *dns.NS:
		if owner == zd.ZoneName {
			zd.NSrrs = append(zd.NSrrs, rr)
			zd.ApexLen++
			tmp = odmap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			odmap.RRtypes[rrtype] = tmp
		} else {
			tmp = odmap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			odmap.RRtypes[rrtype] = tmp
		}
	case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.NSEC3PARAM, *dns.CDS, *dns.CDNSKEY, *dns.DNSKEY:
		// ignore

	default:
		tmp = odmap.RRtypes[rrtype]
		tmp.RRs = append(tmp.RRs, rr)
		odmap.RRtypes[rrtype] = tmp
	}
	zd.Data[owner] = odmap
}

func (zd *ZoneData) WriteTmpFile(lg *log.Logger) (string, error) {
	f, err := os.CreateTemp(viper.GetString("external.tmpdir"), fmt.Sprintf("%s*.zone", zd.ZoneName))
	if err != nil {
		return f.Name(), err
	}

	err = zd.WriteZoneToFile(f)
	if err != nil {
		return f.Name(), err
	}
	return f.Name(), nil
}

func (zd *ZoneData) WriteFile(filename string, lg *log.Logger) (string, error) {
	fname := fmt.Sprintf("%s/%s", viper.GetString("external.filedir"), filename)
	f, err := os.Create(fname)
	if err != nil {
		return fname, err
	}

	err = zd.WriteZoneToFile(f)
	if err != nil {
		return f.Name(), err
	}

	return f.Name(), nil
}

func (zd *ZoneData) WriteZoneToFile(f *os.File) error {
	var err error
	var bytes, totalbytes int
	zonedata := ""
	rrcount := 0

	writer := bufio.NewWriter(f)

	for _, rr := range zd.RRs {
		zonedata += rr.String() + "\n"
		rrcount++
		if rrcount%1000 == 0 {
			bytes, err = writer.WriteString(zonedata)
			if err != nil {
				return err
			}
			totalbytes += bytes
			bytes = 0
			zonedata = ""
		}
	}
	bytes, err = writer.WriteString(zonedata)
	if err != nil {
		return err
	}
	totalbytes += bytes
	writer.Flush()

	return err
}

func InBailiwick(zone string, ns *dns.NS) bool {
	return strings.HasSuffix(ns.Ns, zone)
}

func DropDNSSECp(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
		dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeDNSKEY:
		return false
	}
	return true
}

func DropDNSSECZONEMDp(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
		dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeDNSKEY, dns.TypeZONEMD:
		return false
	}
	return true
}

func (zd *ZoneData) ComputeIndices() {
	if zd.ZoneType == 3 {
		for _, v := range zd.Data {
			zd.Owners = append(zd.Owners, v)
		}
		// quickSort(zd.Owners)
		zd.Data = nil
		zd.OwnerIndex = map[string]int{}
		for i, od := range zd.Owners {
			if zd.Debug {
				zd.Logger.Printf("ComputeIndices: indexing %s", od.Name)
			}
			zd.OwnerIndex[od.Name] = i
		}
		soas := zd.Owners[zd.OwnerIndex[zd.ZoneName]].RRtypes[dns.TypeSOA]
		soas.RRs = soas.RRs[:1]
		zd.Owners[zd.OwnerIndex[zd.ZoneName]].RRtypes[dns.TypeSOA] = soas
	}
}

func (zd *ZoneData) PrintRRs() {
	switch zd.ZoneType {
	case MapZone, RpzZone:
		for _, od := range zd.Data {
			for _, rrt := range od.RRtypes {
				for _, rr := range rrt.RRs {
					PrintRR(rr)
				}
			}
		}

	case SliceZone:
		for _, od := range zd.Owners {
			for _, rrt := range od.RRtypes {
				for _, rr := range rrt.RRs {
					PrintRR(rr)
				}
			}
		}
	}
}

func PrintRR(rr dns.RR) {
	switch rr := rr.(type) {
	case *dns.DNSKEY:
		fmt.Printf("%s\tIN\tDNSKEY\t%d %d %d\t%s...%s [%d]\n",
			rr.Header().Name, rr.Header().Ttl, rr.Header().Rrtype, rr.Header().Class,
			rr.PublicKey[0:30], rr.PublicKey[len(rr.PublicKey)-30:],
			rr.KeyTag())

	case *dns.CDNSKEY:
		fmt.Printf("%s\tIN\tCDNSKEY\t%d %d %d\t%s...%s [%d]\n",
			rr.Header().Name, rr.Header().Ttl, rr.Header().Rrtype, rr.Header().Class,
			rr.PublicKey[0:30], rr.PublicKey[len(rr.PublicKey)-30:],
			rr.KeyTag())

	case *dns.RRSIG:
		fmt.Printf("%s\t%d\tIN\tRRSIG\t%s\t%d %d %d exp='%s' inc='%s' %d %s %s...%s\n",
			rr.Header().Name, rr.Header().Ttl, dns.TypeToString[rr.Header().Rrtype],
			rr.Algorithm, rr.Labels, rr.OrigTtl,
			ParseDNSTime(rr.Expiration).Format("2006-01-02 15:04:05"),
			ParseDNSTime(rr.Inception).Format("2006-01-02 15:04:05"),
			rr.KeyTag, rr.SignerName, rr.Signature[0:20],
			rr.Signature[len(rr.Signature)-20:])

	default:
		fmt.Printf("%s\n", rr.String())
	}
}

func PrintRRs(rrs []dns.RR) {
	for _, rr := range rrs {
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			fmt.Printf("%s\tIN\tDNSKEY\t%d %d %d\t%s...%s [%d]\n",
				rr.Header().Name, rr.Header().Ttl, rr.Header().Rrtype, rr.Header().Class,
				rr.PublicKey[0:30], rr.PublicKey[len(rr.PublicKey)-30:],
				rr.KeyTag())

		case *dns.CDNSKEY:
			fmt.Printf("%s\tIN\tCDNSKEY\t%d %d %d\t%s...%s [%d]\n",
				rr.Header().Name, rr.Header().Ttl, rr.Header().Rrtype, rr.Header().Class,
				rr.PublicKey[0:30], rr.PublicKey[len(rr.PublicKey)-30:],
				rr.KeyTag())

		case *dns.RRSIG:
			fmt.Printf("%s\t%d\tIN\tRRSIG\t%s\t%d %d %d exp='%s' inc='%s' %d %s %s...%s\n",
				rr.Header().Name, rr.Header().Ttl, dns.TypeToString[rr.Header().Rrtype],
				rr.Algorithm, rr.Labels, rr.OrigTtl,
				ParseDNSTime(rr.Expiration).Format("2006-01-02 15:04:05"),
				ParseDNSTime(rr.Inception).Format("2006-01-02 15:04:05"),
				rr.KeyTag, rr.SignerName, rr.Signature[0:20],
				rr.Signature[len(rr.Signature)-20:])

		default:
			fmt.Printf("%s\n", rr.String())
		}
	}
}

func ParseDNSTime(t uint32) time.Time {
	mod := (int64(t)-time.Now().Unix())/year68 - 1
	if mod < 0 {
		mod = 0
	}
	ti := time.Unix(int64(t)-mod*year68, 0).UTC()
	return ti
}
