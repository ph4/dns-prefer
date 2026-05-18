package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
)

const (
	EMPTY = iota
	SUFFIX
	STRICT
	REGEX
)

type DomainRule struct {
	Rule      string
	MatchType int
	Protocol  uint16
	Matcher   *regexp.Regexp
}

var emptyRule = &DomainRule{MatchType: EMPTY}

type CIDRRule struct {
	Prefix   netip.Prefix
	Protocol uint16
}

var (
	upstreamAddress = flag.String("s", "1.1.1.1:53", "upstream dns server")
	listenAddress   = flag.String("l", "0.0.0.0:5367", "listen address")
	cacheExpireTime = flag.Int("e", 3600, "cache expire time")
	cacheSize       = flag.Int("m", 6000, "cache size")
	domainConfPath  = flag.String("c", "/etc/dns-prefer.conf", "domain conf path")
)

var (
	client      = new(dns.Client)
	recordCache *expirable.LRU[string, bool]
	ruleCache   *expirable.LRU[string, *DomainRule]
	domainRules = make([]*DomainRule, 0)
	cidrRules   = make([]*CIDRRule, 0)
)

var validDomainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

func main() {
	flag.Parse()
	loadDomainRules()
	recordCache = expirable.NewLRU[string, bool](*cacheSize, nil, time.Duration(*cacheExpireTime)*time.Second)
	ruleCache = expirable.NewLRU[string, *DomainRule](*cacheSize, nil, time.Duration(*cacheExpireTime)*time.Second)
	dns.HandleFunc(".", dnsRequestHandle)

	server := &dns.Server{Addr: *listenAddress, Net: "udp"}
	log.Printf("Starting DNS server on %s, upstream %s\n", server.Addr, *upstreamAddress)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v\n", err)
	}
}

func dnsRequestHandle(writer dns.ResponseWriter, req *dns.Msg) {
	qName := req.Question[0].Name
	qType := req.Question[0].Qtype

	rule := matchDomain(qName)
	if rule != nil && rule.MatchType != EMPTY && rule.Protocol != qType {
		log.Println("Hit rule:", rule)
		recordExist, err := checkHasRecord(qName, rule.Protocol)
		if err != nil {
			log.Println(err, qName, qTypeString(qType))
			defaultUpstreamHandle(writer, req)
			return
		}
		if recordExist {
			log.Println("Hit block query:", qName)
			emptyResponseHandle(writer, req)
			return
		}
		log.Println("Direct query:", qName)
		defaultUpstreamHandle(writer, req)
		return
	}

	if len(cidrRules) > 0 && rule == nil {
		cidrUpstreamHandle(writer, req)
		return
	}

	defaultUpstreamHandle(writer, req)
}

func cidrUpstreamHandle(writer dns.ResponseWriter, req *dns.Msg) {
	qName := req.Question[0].Name
	qType := req.Question[0].Qtype

	req.RecursionDesired = true
	resp, _, err := client.Exchange(req, *upstreamAddress)
	if err != nil {
		log.Println(err, qName, qTypeString(qType))
		return
	}
	if len(resp.Answer) == 0 {
		if err := writer.WriteMsg(resp); err != nil {
			log.Println("write response failed:", err)
		}
		return
	}
	flattenResponse(resp, qName)

	for _, rr := range resp.Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(v.AAAA.To16())
		default:
			continue
		}

		var hitCIDR *CIDRRule
		for _, cidr := range cidrRules {
			if cidr.Prefix.Contains(ip) {
				hitCIDR = cidr
				break
			}
		}

		if hitCIDR == nil || hitCIDR.Protocol == qType {
			continue
		}
		exist, err := checkHasRecord(qName, hitCIDR.Protocol)
		if err != nil {
			log.Println(err, qName, qTypeString(qType))
			continue
		}
		if exist {
			log.Println("Hit cidr block query:", qName, hitCIDR.Prefix)
			emptyResponseHandle(writer, req)
			ruleCache.Add(qName, &DomainRule{
				MatchType: STRICT,
				Protocol:  hitCIDR.Protocol,
				Rule:      qName,
			})
			return
		}
	}

	if err := writer.WriteMsg(resp); err != nil {
		log.Println("write response failed:", err)
	}
	ruleCache.Add(qName, emptyRule)
}

func defaultUpstreamHandle(writer dns.ResponseWriter, req *dns.Msg) {
	req.RecursionDesired = true
	resp, _, err := client.Exchange(req, *upstreamAddress)
	if err != nil {
		log.Println(err, req.Question[0].Name, qTypeString(req.Question[0].Qtype))
		return
	}
	if len(resp.Answer) > 0 {
		flattenResponse(resp, req.Question[0].Name)
	}
	if err := writer.WriteMsg(resp); err != nil {
		log.Println("write response failed:", err)
	}
}

func emptyResponseHandle(writer dns.ResponseWriter, req *dns.Msg) {
	resp := &dns.Msg{}
	resp.SetReply(req)
	if err := writer.WriteMsg(resp); err != nil {
		log.Println("write response failed:", err)
	}
}

func checkHasRecord(domain string, qType uint16) (bool, error) {
	if cache, exist := recordCache.Get(getRecordCacheKey(domain, qType)); exist {
		return cache, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(domain, qType)
	m.RecursionDesired = true

	r, _, err := client.Exchange(m, *upstreamAddress)
	if err != nil {
		return false, err
	}

	exist := false
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			if ans.Header().Rrtype == qType {
				exist = true
				break
			}
		}
	}

	recordCache.Add(getRecordCacheKey(domain, qType), exist)
	return exist, nil
}

func getRecordCacheKey(domain string, qType uint16) string {
	return fmt.Sprintf("%s:%d", domain, qType)
}

func flattenResponse(r *dns.Msg, originalName string) {
	filtered := r.Answer[:0]
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			rr.Header().Name = originalName
		}
		filtered = append(filtered, rr)
	}
	r.Answer = filtered
}

func matchDomain(domain string) *DomainRule {
	if cache, exist := ruleCache.Get(domain); exist {
		return cache
	}

	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	if domain == "" {
		return nil
	}

	var matched *DomainRule
	for _, rule := range domainRules {
		switch rule.MatchType {
		case SUFFIX:
			suffix := rule.Rule
			if suffix[0] != '.' {
				if rule.Rule == domain {
					matched = rule
					break
				}
				suffix = "." + suffix
			}
			if strings.HasSuffix(domain, suffix) {
				matched = rule
			}
		case STRICT:
			if rule.Rule == domain {
				matched = rule
			}
		case REGEX:
			if rule.Matcher.MatchString(domain) {
				matched = rule
			}
		}
		if matched != nil {
			break
		}
	}

	ruleCache.Add(domain, matched)
	return matched
}

func (r *DomainRule) String() string {
	var matchType string
	switch r.MatchType {
	case SUFFIX:
		matchType = "SUFFIX"
	case STRICT:
		matchType = "STRICT"
	case REGEX:
		matchType = "REGEX"
	}
	return fmt.Sprintf("Rule: %s, match type: %s, query type: %s", r.Rule, matchType, qTypeString(r.Protocol))
}

func loadDomainRules() {
	if *domainConfPath == "" {
		return
	}
	file, err := os.Open(*domainConfPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println(err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		length := len(line)
		if line == "" || line[0] == '@' || line[0] == '#' {
			continue
		}
		if length < 3 {
			log.Println("Invalid rule:", line)
			continue
		}
		if line[length-2] != '@' || line[0] == ':' {
			log.Println("Invalid rule:", line)
			continue
		}

		var protocol uint16
		switch line[length-1] {
		case '4':
			protocol = dns.TypeA
		case '6':
			protocol = dns.TypeAAAA
		default:
			log.Println("Invalid rule:", line)
			continue
		}

		result := strings.SplitN(line, ":", 2)
		if len(result) == 1 {
			domain := line[:length-2]
			if !isValidDomain(domain) {
				log.Println("Invalid rule:", line)
				continue
			}
			domainRules = append(domainRules, &DomainRule{
				Rule:      domain,
				MatchType: SUFFIX,
				Protocol:  protocol,
			})
			continue
		}

		switch result[0] {
		case "cidr":
			cidr := result[1][:len(result[1])-2]
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				log.Println("Invalid rule:", line)
				continue
			}
			cidrRules = append(cidrRules, &CIDRRule{
				Prefix:   prefix.Masked(),
				Protocol: protocol,
			})
		case "strict":
			domain := result[1][:len(result[1])-2]
			if !isValidDomain(domain) {
				log.Println("Invalid rule:", line)
				continue
			}
			domainRules = append(domainRules, &DomainRule{
				Rule:      domain,
				MatchType: STRICT,
				Protocol:  protocol,
			})
		case "regex":
			pattern := result[1][:len(result[1])-2]
			if len(pattern) == 0 {
				log.Println("Invalid rule:", line)
				continue
			}
			matcher, err := regexp.Compile(pattern)
			if err != nil {
				log.Println("Invalid rule:", line)
				continue
			}
			domainRules = append(domainRules, &DomainRule{
				Rule:      pattern,
				MatchType: REGEX,
				Protocol:  protocol,
				Matcher:   matcher,
			})
		default:
			log.Println("Invalid rule:", line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func isValidDomain(s string) bool {
	return len(s) > 0 && len(s) <= 253 && validDomainRegex.MatchString(s)
}

func qTypeString(qType uint16) string {
	switch qType {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("%d", qType)
	}
}
