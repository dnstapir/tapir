// Copyright 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 *
 */
package tapir

import (
	"github.com/miekg/dns"
	"log"
)

func (zd *ZoneData) FindGlue(nsrrs RRset) *RRset {
	zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	var glue, maybe_glue RRset
	var nsname string
	child := nsrrs.RRs[0].Header().Name
	for _, rr := range nsrrs.RRs {
		if nsrr, ok := rr.(*dns.NS); ok {
			nsname = nsrr.Ns
			zd.Logger.Printf("FindGlue: child '%s' has a nameserver '%s'", child, nsname)

			var nsnamerrs *OwnerData

			switch zd.ZoneType {
			case 3:
				nsnidx := zd.OwnerIndex[nsname]
				nsnamerrs = &zd.Owners[nsnidx]
			case 2:
				tmp := zd.Data[nsname]
				nsnamerrs = &tmp
			}

			if nsnamerrs != nil {
				log.Printf("FindGlue nsname='%s': there are RRs", nsname)
				if ns_A_rrs, ok := nsnamerrs.RRtypes[dns.TypeA]; ok {
					log.Printf("FindGlue for nsname='%s': there are A RRs", nsname)
					// Ok, we found an A RR
					maybe_glue.RRs = append(maybe_glue.RRs, ns_A_rrs.RRs...)
				}
				if ns_AAAA_rrs, ok := nsnamerrs.RRtypes[dns.TypeAAAA]; ok {
					log.Printf("FindGlue for nsname='%s': there are AAAA RRs", nsname)
					// Ok, we found an AAAA RR
					maybe_glue.RRs = append(maybe_glue.RRs, ns_AAAA_rrs.RRs...)
				}
			}
		}
	}

	if len(maybe_glue.RRs) == 0 {
		log.Printf("FindGlue: no glue for child=%s found in %s", child, zd.ZoneName)
	} else {
		log.Printf("FindGlue: found %d glue RRs child=%s in %s",
			len(glue.RRs), child, zd.ZoneName)
		glue = maybe_glue
	}
	return &glue
}
