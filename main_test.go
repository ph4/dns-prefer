package main

import (
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
)

func resetGlobals() {
	domainRules = make([]*DomainRule, 0)
	cidrRules = make([]*CIDRRule, 0)
	recordCache = expirable.NewLRU[string, bool](100, nil, time.Minute)
	ruleCache = expirable.NewLRU[string, *DomainRule](100, nil, time.Minute)
}

// --- isValidDomain ---

func TestIsValidDomain(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"a.b.c.d.e.f", true},
		{"xn--p1ai", true},
		{"a", true},
		{"*.google.com", true},
		{"", false},
		{"google..com", false},
		{"-google.com", false},
		{"google-.com", false},
		{"go ogle.com", false},
	}
	for _, c := range cases {
		got := isValidDomain(c.input)
		if got != c.want {
			t.Errorf("isValidDomain(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

// --- qTypeString ---

func TestQTypeString(t *testing.T) {
	if s := qTypeString(dns.TypeA); s != "A" {
		t.Errorf("got %q, want A", s)
	}
	if s := qTypeString(dns.TypeAAAA); s != "AAAA" {
		t.Errorf("got %q, want AAAA", s)
	}
	if s := qTypeString(dns.TypeMX); s != "15" {
		t.Errorf("got %q, want 15", s)
	}
}

// --- getRecordCacheKey ---

func TestGetRecordCacheKey(t *testing.T) {
	key := getRecordCacheKey("example.com.", dns.TypeA)
	if key != "example.com.:1" {
		t.Errorf("unexpected key: %q", key)
	}
	key2 := getRecordCacheKey("example.com.", dns.TypeAAAA)
	if key2 != "example.com.:28" {
		t.Errorf("unexpected key: %q", key2)
	}
}

// --- DomainRule.String ---

func TestDomainRuleString(t *testing.T) {
	r := &DomainRule{Rule: "google.com", MatchType: SUFFIX, Protocol: dns.TypeA}
	s := r.String()
	if s == "" {
		t.Error("String() returned empty")
	}

	r2 := &DomainRule{Rule: "youtube.com", MatchType: STRICT, Protocol: dns.TypeAAAA}
	s2 := r2.String()
	if s2 == "" {
		t.Error("String() returned empty")
	}

	r3 := &DomainRule{Rule: `.*\.bilibili\.com`, MatchType: REGEX, Protocol: dns.TypeA}
	s3 := r3.String()
	if s3 == "" {
		t.Error("String() returned empty")
	}
}

// --- flattenResponse ---

func TestFlattenResponse_RemovesCNAME(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "example.com.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		},
	}
	flattenResponse(msg, "www.example.com.")
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	if msg.Answer[0].Header().Rrtype != dns.TypeA {
		t.Error("expected A record to remain")
	}
	if msg.Answer[0].Header().Name != "www.example.com." {
		t.Errorf("expected name rewritten to www.example.com., got %q", msg.Answer[0].Header().Name)
	}
}

func TestFlattenResponse_AAAARenamed(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("::1"),
		},
	}
	flattenResponse(msg, "original.example.com.")
	if msg.Answer[0].Header().Name != "original.example.com." {
		t.Errorf("name not rewritten, got %q", msg.Answer[0].Header().Name)
	}
}

func TestFlattenResponse_EmptyAnswer(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{}
	flattenResponse(msg, "example.com.")
	if len(msg.Answer) != 0 {
		t.Error("expected empty answer to stay empty")
	}
}

// --- matchDomain ---

func setupMatchDomainRules() {
	resetGlobals()
	domainRules = []*DomainRule{
		{Rule: "google.com", MatchType: SUFFIX, Protocol: dns.TypeA},
		{Rule: "www.youtube.com", MatchType: STRICT, Protocol: dns.TypeA},
		{Rule: `.*\.bilibili\.com`, MatchType: REGEX, Protocol: dns.TypeA, Matcher: mustCompile(`.*\.bilibili\.com`)},
	}
}

func mustCompile(pattern string) *regexp.Regexp {
	r, _ := regexp.Compile(pattern)
	return r
}

func TestMatchDomain_SuffixMatch(t *testing.T) {
	setupMatchDomainRules()

	cases := []struct {
		domain  string
		wantNil bool
	}{
		{"google.com.", false},
		{"www.google.com.", false},
		{"sub.google.com.", false},
		{"notgoogle.com.", true},
		{"youtube.com.", true},
	}
	for _, c := range cases {
		rule := matchDomain(c.domain)
		if c.wantNil && rule != nil {
			t.Errorf("matchDomain(%q) expected nil, got %v", c.domain, rule)
		}
		if !c.wantNil && rule == nil {
			t.Errorf("matchDomain(%q) expected match, got nil", c.domain)
		}
		if !c.wantNil && rule != nil && rule.MatchType != SUFFIX {
			t.Errorf("matchDomain(%q) expected SUFFIX, got %d", c.domain, rule.MatchType)
		}
	}
}

func TestMatchDomain_WildcardSuffixMatch(t *testing.T) {
	resetGlobals()
	domainRules = []*DomainRule{
		{Rule: "*.google.com", MatchType: SUFFIX, Protocol: dns.TypeA},
	}

	cases := []struct {
		domain  string
		wantNil bool
	}{
		{"www.google.com.", false},
		{"sub.google.com.", false},
		{"google.com.", true}, // apex excluded
	}
	for _, c := range cases {
		rule := matchDomain(c.domain)
		if c.wantNil && rule != nil {
			t.Errorf("matchDomain(%q) expected nil, got %v", c.domain, rule)
		}
		if !c.wantNil && rule == nil {
			t.Errorf("matchDomain(%q) expected match, got nil", c.domain)
		}
	}
}

func TestMatchDomain_StrictMatch(t *testing.T) {
	setupMatchDomainRules()

	rule := matchDomain("www.youtube.com.")
	if rule == nil || rule.MatchType != STRICT {
		t.Errorf("expected STRICT match for www.youtube.com., got %v", rule)
	}

	rule2 := matchDomain("youtube.com.")
	if rule2 != nil {
		t.Errorf("youtube.com. should not match strict www.youtube.com. rule, got %v", rule2)
	}
}

func TestMatchDomain_RegexMatch(t *testing.T) {
	setupMatchDomainRules()

	rule := matchDomain("www.bilibili.com.")
	if rule == nil || rule.MatchType != REGEX {
		t.Errorf("expected REGEX match for www.bilibili.com., got %v", rule)
	}

	rule2 := matchDomain("bilibili.com.")
	if rule2 != nil {
		t.Errorf("bilibili.com. should not match regex, got %v", rule2)
	}
}

func TestMatchDomain_EmptyDomain(t *testing.T) {
	setupMatchDomainRules()
	rule := matchDomain("")
	if rule != nil {
		t.Errorf("empty domain should return nil, got %v", rule)
	}
}

func TestMatchDomain_CachesResult(t *testing.T) {
	setupMatchDomainRules()
	_ = matchDomain("google.com.")
	_, found := ruleCache.Get("google.com.")
	if !found {
		t.Error("expected result to be cached after match")
	}
}

// --- loadDomainRules ---

func writeTempConf(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "dns-filter-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoadDomainRules_SuffixRule(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, "google.com@4\n")
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 1 {
		t.Fatalf("expected 1 domain rule, got %d", len(domainRules))
	}
	r := domainRules[0]
	if r.MatchType != SUFFIX || r.Rule != "google.com" || r.Protocol != dns.TypeA {
		t.Errorf("unexpected rule: %+v", r)
	}
}

func TestLoadDomainRules_StrictRule(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, "strict:www.youtube.com@6\n")
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 1 {
		t.Fatalf("expected 1 domain rule, got %d", len(domainRules))
	}
	r := domainRules[0]
	if r.MatchType != STRICT || r.Rule != "www.youtube.com" || r.Protocol != dns.TypeAAAA {
		t.Errorf("unexpected rule: %+v", r)
	}
}

func TestLoadDomainRules_RegexRule(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, `regex:.*\.bilibili\.com@4`+"\n")
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 1 {
		t.Fatalf("expected 1 domain rule, got %d", len(domainRules))
	}
	r := domainRules[0]
	if r.MatchType != REGEX || r.Protocol != dns.TypeA {
		t.Errorf("unexpected rule: %+v", r)
	}
	if r.Matcher == nil {
		t.Error("regex matcher should not be nil")
	}
}

func TestLoadDomainRules_CIDRRule(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, "cidr:192.168.0.0/16@6\n")
	*domainConfPath = path
	loadDomainRules()

	if len(cidrRules) != 1 {
		t.Fatalf("expected 1 cidr rule, got %d", len(cidrRules))
	}
	r := cidrRules[0]
	if r.Protocol != dns.TypeAAAA {
		t.Errorf("expected TypeAAAA, got %d", r.Protocol)
	}
	expected, _ := netip.ParsePrefix("192.168.0.0/16")
	if r.Prefix != expected.Masked() {
		t.Errorf("unexpected prefix: %v", r.Prefix)
	}
}

func TestLoadDomainRules_CommentsAndBlanksIgnored(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, `# comment
@ignored
google.com@4
`)
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 1 {
		t.Errorf("expected 1 rule, got %d (comments/blanks should be skipped)", len(domainRules))
	}
}

func TestLoadDomainRules_InvalidRulesSkipped(t *testing.T) {
	resetGlobals()
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	path := writeTempConf(t, `ab
a
:#6
strict:@4
invalid.domain..com@4
notacidr:1.2.3@4
badprotocol.com@5
`)
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 0 {
		t.Errorf("expected 0 valid rules, got %d", len(domainRules))
	}
	if len(cidrRules) != 0 {
		t.Errorf("expected 0 cidr rules, got %d", len(cidrRules))
	}
}

func TestLoadDomainRules_MultipleRules(t *testing.T) {
	resetGlobals()
	path := writeTempConf(t, `google.com@4
strict:www.youtube.com@6
regex:.*\.bilibili\.com@4
cidr:10.0.0.0/8@6
`)
	*domainConfPath = path
	loadDomainRules()

	if len(domainRules) != 3 {
		t.Errorf("expected 3 domain rules, got %d", len(domainRules))
	}
	if len(cidrRules) != 1 {
		t.Errorf("expected 1 cidr rule, got %d", len(cidrRules))
	}
}

func TestLoadDomainRules_EmptyPath(t *testing.T) {
	resetGlobals()
	*domainConfPath = ""
	loadDomainRules() // should not panic
	if len(domainRules) != 0 || len(cidrRules) != 0 {
		t.Error("expected no rules when path is empty")
	}
}

// --- emptyResponseHandle ---

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *testResponseWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *testResponseWriter) Close() error                { return nil }
func (w *testResponseWriter) TsigStatus() error           { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)         {}
func (w *testResponseWriter) Hijack()                     {}

func TestEmptyResponseHandle(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeAAAA)

	w := &testResponseWriter{}
	emptyResponseHandle(w, req)

	if w.msg == nil {
		t.Fatal("expected response to be written")
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("expected empty answer, got %d records", len(w.msg.Answer))
	}
	if !w.msg.Response {
		t.Error("expected response flag to be set")
	}
}
