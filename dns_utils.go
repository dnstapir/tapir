/*
 * Johan Stenstam, johani@johani.org
 */
package tapir

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	// "github.com/DmitriyVTitov/size"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const (
	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits
	timelayout = "2006-01-02 15:04:05"
)

// TODO: Add support for TSIG zone transfers.

// keepfunc(rrtype) is a predicate that is used to decide whether to include a particular
// RRtype in the resulting, kept, zonedata. Used to filter out DNSSEC RRs if needed.

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

	if zd.ZoneType == 2 || zd.ZoneType == 3 {
		zd.Data = make(map[string]OwnerData, 30)
	}
	log.Printf("ZoneTransferIn: ZoneType: %v", zd.ZoneType)

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
			zd.Logger.Printf("ZoneTransfer: zone %s error: %v", zd.ZoneName, envelope.Error)
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

	//	zd.Logger.Printf("ZoneTransferIn: %s: dropped %d RRs (filter), kept %d apex RRs + %d BodyRRs",
	//		zd.ZoneName, zd.DroppedRRs, zd.ApexLen, len(zd.BodyRRs))
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

func (zd *ZoneData) ZoneTransferOut(w dns.ResponseWriter, r *dns.Msg) (int, error) {

	if zd.Verbose {
		zd.Logger.Printf("ZoneTransferOut: Will try to serve zone %s (%d RRs) to  %v\n", zd.ZoneName,
			len(zd.RRs), w.RemoteAddr().String())
	}

	zone := dns.Fqdn(zd.ZoneName)
	if zd.ZoneType != RpzZone {
		zd.Sync()
	}

	if zd.Verbose {
		zd.Logger.Printf("ZoneTransferOut: Will try to serve zone %s (%d RRs) to  %v\n", zone,
			len(zd.RRs), w.RemoteAddr().String())
	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		tr.Out(w, r, outbound_xfr)
		wg.Done()
	}()

	count := 0
	send_count := 0
	env := dns.Envelope{}

	//	env.RR = append(env.RR, dns.RR(&zd.SOA))
	//	total_sent := 1
	var total_sent int

	switch zd.ZoneType {
	case RpzZone:
		env.RR = append(env.RR, dns.RR(&zd.SOA))
		env.RR = append(env.RR, zd.NSrrs...)
		// for _, rr := range zd.RRs {
		for _, rpzn := range zd.RpzMap {
			env.RR = append(env.RR, *rpzn.RR) // should do proper slice magic instead
			count++
			if count >= 500 {
				send_count++
				total_sent += len(env.RR)
				// fmt.Printf("Sending %d RRs\n", len(env.RR))
				outbound_xfr <- &env
				// fmt.Printf("Sent %d RRs: done\n", len(env.RR))
				env = dns.Envelope{}
				count = 0
			}
		}

	case SliceZone:
		for _, ownerdata := range zd.Owners {
			for rrt, rrset := range ownerdata.RRtypes {
				if ownerdata.Name == zd.ZoneName {
					zd.Logger.Printf("Apex: %s\t%s\n", zd.ZoneName, dns.TypeToString[rrt])
				}

				switch rrt {
				case dns.TypeSOA, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
					continue
				}

				for _, rr := range rrset.RRs {
					env.RR = append(env.RR, rr) // should do proper slice magic instead
					count++
					if count >= 500 {
						send_count++
						total_sent += len(env.RR)
						// fmt.Printf("Sending %d RRs\n", len(env.RR))
						outbound_xfr <- &env
						// fmt.Printf("Sent %d RRs: done\n", len(env.RR))
						env = dns.Envelope{}
						count = 0
					}
				}
			}
		}
	}

	env.RR = append(env.RR, dns.RR(&zd.SOA)) // trailing SOA

	total_sent += len(env.RR)
	zd.Logger.Printf("ZoneTransferOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zd.ZoneName, len(env.RR), total_sent)
	outbound_xfr <- &env

	close(outbound_xfr)
	wg.Wait() // wait until everything is written out
	w.Close() // close connection

	zd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)

	return total_sent - 1, nil
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

	if zd.ZoneType == 2 || zd.ZoneType == 3 {
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
		return zd.SOA.Serial, fmt.Errorf("Error from ZoneParser: %v", err)
	}
	zd.Logger.Printf("*** Zone %s read from file. No errors.", zd.ZoneName)

	zd.ComputeIndices() // for zonetype 3, otherwise no-op

	// fmt.Printf("ReadZoneFile: Size: zoneparser: %d zd.RRs: %d\n", size.Of(zp), size.Of(zd.RRs))

	zd.XfrType = "axfr" // XXX: technically not true, but the distinction is between complete zone and "diff"

	//	zd.Logger.Printf("ReadZoneFile: %s: dropped %d RRs (filter), kept %d apex RRs + %d BodyRRs",
	//		zd.ZoneName, zd.DroppedRRs, zd.ApexLen, len(zd.BodyRRs))
	zd.Logger.Printf("ReadZoneFile: %s: dropped %d RRs (filter), kept %d apex RRs",
		zd.ZoneName, zd.DroppedRRs, zd.ApexLen)

	return zd.SOA.Serial, nil
}

func (zd *ZoneData) RRSortFunc(rr dns.RR, first_soa *dns.SOA) {
//	if zd.RRKeepFunc != nil && !zd.RRKeepFunc(rr.Header().Rrtype) {
//		zd.DroppedRRs++
//		return
//	}
	zd.KeptRRs++

	if zd.RRParseFunc != nil && !zd.RRParseFunc(&rr, zd) {
		zd.DroppedRRs++
		return
	}

	owner := rr.Header().Name
	rrtype := rr.Header().Rrtype

	// zd.Logger.Printf("RRSortFunc: owner=%s rrtype=%s", owner, dns.TypeToString[rrtype])

	var odmap OwnerData
	switch zd.ZoneType {
	case 3:
		fallthrough // store slicezones as mapzones during inbound transfer, sort afterwards into slice
	case 2:
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
		// odmap.RRtypes[rrtype].RRs = append(odmap.RRtypes[rrtype].RRs, rr)
	case *dns.NS:
		if owner == zd.ZoneName {
			zd.NSrrs = append(zd.NSrrs, rr)
			zd.ApexLen++
			tmp = odmap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			odmap.RRtypes[rrtype] = tmp
			// odmap.RRtypes[rrtype].RRs = append(odmap.RRtypes[rrtype].RRs, rr)
		} else {
			tmp = odmap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			odmap.RRtypes[rrtype] = tmp
			// odmap.RRtypes[rrtype].RRs = append(odmap.RRtypes[rrtype].RRs, rr)
		}
	case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.NSEC3PARAM, *dns.CDS, *dns.CDNSKEY, *dns.DNSKEY:
		// ignore

	default:
		// log.Printf("RRSortFunc: owner=%s, rrtype=%s", owner, dns.TypeToString[rrtype])
		tmp = odmap.RRtypes[rrtype]
		tmp.RRs = append(tmp.RRs, rr)
		odmap.RRtypes[rrtype] = tmp
	}
	// zd.Logger.Printf("ZoneName: %s, zonetype: %d", zd.ZoneName, zd.ZoneType)
	zd.Data[owner] = odmap
	return
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
			// fmt.Printf("Size(zonedata): %d\n", size.Of(zonedata))
			zonedata = ""
		}
	}
	bytes, err = writer.WriteString(zonedata)
	if err != nil {
		return err
	}
	totalbytes += bytes
	// fmt.Printf("Size(zonedata): %d\n", size.Of(zonedata))
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
	if zd.Debug {
//		zd.PrintOwners()
	}
}

func (zd *ZoneData) PrintRRs() {
	switch zd.ZoneType {
	case 2:
		for _, od := range zd.Data {
			for _, rrt := range od.RRtypes {
				for _, rr := range rrt.RRs {
					PrintRR(rr)
				}
			}
		}

	case 3:
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
	switch rr.(type) {
	case *dns.DNSKEY:
		k, _ := rr.(*dns.DNSKEY)
		fmt.Printf("%s\tIN\tDNSKEY\t%d %d %d\t%s...%s [%d]\n",
			k.Header().Name, k.Flags, k.Protocol, k.Algorithm,
			k.PublicKey[0:30], k.PublicKey[len(k.PublicKey)-30:],
			k.KeyTag())

	case *dns.CDNSKEY:
		c, _ := rr.(*dns.CDNSKEY)
		fmt.Printf("%s\tIN\tCDNSKEY\t%d %d %d\t%s...%s [%d]\n",
			c.Header().Name, c.Flags, c.Protocol, c.Algorithm,
			c.PublicKey[0:30], c.PublicKey[len(c.PublicKey)-30:],
			c.KeyTag())

	case *dns.RRSIG:
		rs, _ := rr.(*dns.RRSIG)
		fmt.Printf("%s\t%d\tIN\tRRSIG\t%s\t%d %d %d exp='%s' inc='%s' %d %s %s...%s\n",
			rs.Header().Name, rs.Header().Ttl, dns.TypeToString[rs.TypeCovered],
			rs.Algorithm, rs.Labels, rs.OrigTtl,
			ParseDNSTime(rs.Expiration).Format("2006-01-02 15:04:05"),
			ParseDNSTime(rs.Inception).Format("2006-01-02 15:04:05"),
			rs.KeyTag, rs.SignerName, rs.Signature[0:20],
			rs.Signature[len(rs.Signature)-20:])

	default:
		fmt.Printf("%s\n", rr.String())
	}
}

func PrintRRs(rrs []dns.RR) {
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.DNSKEY:
			k, _ := rr.(*dns.DNSKEY)
			fmt.Printf("%s\tIN\tDNSKEY\t%d %d %d\t%s...%s [%d]\n",
				k.Header().Name, k.Flags, k.Protocol, k.Algorithm,
				k.PublicKey[0:30], k.PublicKey[len(k.PublicKey)-30:],
				k.KeyTag())

		case *dns.CDNSKEY:
			c, _ := rr.(*dns.CDNSKEY)
			fmt.Printf("%s\tIN\tCDNSKEY\t%d %d %d\t%s...%s [%d]\n",
				c.Header().Name, c.Flags, c.Protocol, c.Algorithm,
				c.PublicKey[0:30], c.PublicKey[len(c.PublicKey)-30:],
				c.KeyTag())

		case *dns.RRSIG:
			rs, _ := rr.(*dns.RRSIG)
			fmt.Printf("%s\t%d\tIN\tRRSIG\t%s\t%d %d %d exp='%s' inc='%s' %d %s %s...%s\n",
				rs.Header().Name, rs.Header().Ttl, dns.TypeToString[rs.TypeCovered],
				rs.Algorithm, rs.Labels, rs.OrigTtl,
				ParseDNSTime(rs.Expiration).Format("2006-01-02 15:04:05"),
				ParseDNSTime(rs.Inception).Format("2006-01-02 15:04:05"),
				rs.KeyTag, rs.SignerName, rs.Signature[0:20],
				rs.Signature[len(rs.Signature)-20:])

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