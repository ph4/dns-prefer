package main

import (
	"flag"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

var UpstreamAddress = flag.String("s", "1.1.1.1:53", "upstream dns server")
var ListenAddress = flag.String("l", "0.0.0.0:5367", "listen address")
var CacheExpireTime = flag.Int("e", 1800, "cache expire time")

var C *cache.Cache

func main() {
	flag.Parse()
	if *CacheExpireTime != 0 {
		C = cache.New(time.Duration(*CacheExpireTime)*time.Second, 30*time.Second)
	}
	dns.HandleFunc(".", HandleDNSRequest)

	server := &dns.Server{Addr: *ListenAddress, Net: "udp"}
	log.Printf("Starting DNS server on %s, upstream %s\n", server.Addr, *UpstreamAddress)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v\n", err)
	}
}

func HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	c := new(dns.Client)
	c.Net = "udp"

	var upstreamDNS = *UpstreamAddress

	resp, _, err := c.Exchange(req, upstreamDNS)

	if err != nil {
		log.Printf("Query upstream DNS error: %v\n", err)
		return
	}

	defer writer.WriteMsg(resp)

	if len(req.Question) != 1 || len(resp.Answer) == 0 {
		return
	}

	if req.Question[0].Qtype != dns.TypeAAAA {
		return
	}

	// If query type is AAAA, try to check A record

	if C != nil {
		// Check with cache
		if hasA, exist := C.Get(req.Question[0].Name); exist {
			if hasA.(bool) {
				resp.Answer = make([]dns.RR, 0)
			}
			return
		}
	}

	// Check with query
	m := new(dns.Msg)
	m.SetQuestion(req.Question[0].Name, dns.TypeA)
	r, _, err := c.Exchange(m, upstreamDNS)
	if err != nil {
		log.Printf("Query upstream DNS error: %v\n", err)
		return
	}
	if len(r.Answer) == 0 {
		return
	}
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			setARecordCache(req.Question[0].Name, true)
			// Block AAAA response
			resp.Answer = make([]dns.RR, 0)
			return
		} else {
			setARecordCache(req.Question[0].Name, false)
		}
	}
}

func setARecordCache(name string, hasA bool) {
	if C != nil {
		C.SetDefault(name, hasA)
	}
}
