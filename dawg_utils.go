/*
 * Copyright (c) DNS TAPIR
 */
package tapir

import (
	"bufio"
	"fmt"
	"os"

	"encoding/csv"
	"io"
	"log"
	"slices"

	"github.com/miekg/dns"

	"github.com/smhanov/dawg"
)

func ParseCSV(srcfile string, dstmap map[string]*TapirName, dontsort bool) ([]string, error) {
	ifd, err := os.Open(srcfile)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := ifd.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sortedDomains := []string{}
	csvReader := csv.NewReader(ifd)

	// Skip the first line containing the header
	_, err = csvReader.Read()
	if err != nil {
		return nil, err
	}

	var name string
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		name = dns.Fqdn(record[1])
		if dontsort {
			dstmap[name] = &TapirName{Name: name}
		} else {

			// Make sure the domain is fully qualified (includes
			// the root domain dot at the end) as this is expected
			// by miekg/dns when comparing against a dns question
			// section name
			sortedDomains = append(sortedDomains, name)
		}
	}

	if dontsort {
		return []string{}, nil
	}
	fmt.Println("Creating sorted domain list from CSV")
	// The names need to be sorted when adding them to the dawg
	// datastructure otherwise the operation can fail:
	// panic: d.AddWord(): Words not in alphabetical order
	slices.Sort(sortedDomains)
	return sortedDomains, nil
}

// Two modes of operation: either return a (potentially large) []string with sorted output
// *or* update the dstmap of TapirNames directly and don't return the result
func ParseText(srcfile string, dstmap map[string]*TapirName, dontsort bool) ([]string, error) {
	ifd, err := os.Open(srcfile)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := ifd.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sortedDomains := []string{}

	scanner := bufio.NewScanner(ifd)
	scanner.Split(bufio.ScanLines)

	if dontsort {
		for scanner.Scan() {
			// sortedDomains = append(sortedDomains, dns.Fqdn(scanner.Text()))
			name := dns.Fqdn(scanner.Text())
			dstmap[name] = &TapirName{Name: name}
		}
		return sortedDomains, nil //
	} else {
		// fmt.Println("Creating sorted domain list from text")
		for scanner.Scan() {
			sortedDomains = append(sortedDomains, dns.Fqdn(scanner.Text()))
		}
		slices.Sort(sortedDomains)
		return sortedDomains, nil
	}
}

func CreateDawg(sortedDomains []string, outfile string) error {
	fmt.Printf("Creating DAWG data structure\n")
	dawg := dawg.New()
	for _, domain := range sortedDomains {
		dawg.Add(domain)
		if GlobalCF.Debug {
			fmt.Printf("Added \"%s\" to DAWG\n", domain)
		}
	}

	finder := dawg.Finish()

	fmt.Printf("Saving DAWG to file %s\n", outfile)
	_, err := finder.Save(outfile)
	if err != nil {
		return err
	}

	return nil
}

// XXX: This is a slow and costly operation. Do not use unnecessarily.
func ListDawg(df dawg.Finder) (int, []string) {
	count := 0
	var result []string
	enumfn := func(idx int, s []rune, final bool) int {
		count++
		if final {
			result = append(result, string(s))
		}
		return dawg.Continue
	}

	df.Enumerate(enumfn)
	return count, result
}
