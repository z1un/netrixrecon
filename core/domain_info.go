package core

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/z1un/netrixrecon/utils"
)

type DNSResolver struct {
	servers []string
}

func NewDNSResolver(servers []string) *DNSResolver {
	if len(servers) == 0 {
		servers = utils.DefaultNameservers
	}
	return &DNSResolver{
		servers: servers,
	}
}

func (r *DNSResolver) query(domain string, qtype uint16) []dns.RR {
	if resp := r.queryAll(domain, qtype); resp != nil {
		return resp.Answer
	}
	return nil
}

func (r *DNSResolver) queryAll(domain string, qtype uint16) *dns.Msg {
	type result struct {
		resp *dns.Msg
		err  error
	}

	ch := make(chan result, len(r.servers))

	for _, server := range r.servers {
		go func(srv string) {
			c := &dns.Client{Timeout: 5 * time.Second}
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), qtype)
			m.SetEdns0(4096, false)
			resp, _, err := c.Exchange(m, srv)
			ch <- result{resp, err}
		}(server)
	}

	for i := 0; i < len(r.servers); i++ {
		r := <-ch
		if r.err == nil && r.resp != nil && r.resp.Rcode == dns.RcodeSuccess {
			return r.resp
		}
	}
	return nil
}

func (r *DNSResolver) ResolveA(domain string) []string {
	answers := r.query(domain, dns.TypeA)
	var ips []string
	for _, ans := range answers {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}

func (r *DNSResolver) ResolveAAAA(domain string) []string {
	answers := r.query(domain, dns.TypeAAAA)
	var ips []string
	for _, ans := range answers {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA.String())
		}
	}
	return ips
}

func (r *DNSResolver) GetNS(domain string) []string {
	answers := r.query(domain, dns.TypeNS)
	var ns []string
	for _, ans := range answers {
		if n, ok := ans.(*dns.NS); ok {
			ns = append(ns, strings.TrimSuffix(n.Ns, "."))
		}
	}
	return ns
}

func (r *DNSResolver) GetMX(domain string) []string {
	answers := r.query(domain, dns.TypeMX)
	var mx []string
	for _, ans := range answers {
		if m, ok := ans.(*dns.MX); ok {
			target := strings.TrimSuffix(m.Mx, ".")
			if target == "" {
				continue
			}
			ips := r.ResolveA(target)
			ipStr := strings.Join(ips, ", ")
			if ipStr != "" {
				mx = append(mx, fmt.Sprintf("%s [%s] (Priority %d)", target, ipStr, m.Preference))
			} else {
				mx = append(mx, fmt.Sprintf("%s (Priority %d)", target, m.Preference))
			}
		}
	}
	return mx
}

func (r *DNSResolver) GetSOA(domain string) map[string]interface{} {
	resp := r.queryAll(domain, dns.TypeSOA)
	if resp == nil {
		return nil
	}
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return map[string]interface{}{
				"primary_ns":     strings.TrimSuffix(soa.Ns, "."),
				"primary_ns_ips": r.ResolveA(strings.TrimSuffix(soa.Ns, ".")),
				"admin_email":    strings.Replace(strings.TrimSuffix(soa.Mbox, "."), ".", "@", 1),
				"serial":         soa.Serial,
				"refresh":        soa.Refresh,
				"retry":          soa.Retry,
				"expire":         soa.Expire,
				"ttl":            soa.Minttl,
			}
		}
	}
	return nil
}

func (r *DNSResolver) GetCNAME(domain string) string {
	resp := r.queryAll(domain, dns.TypeCNAME)
	if resp == nil {
		return ""
	}
	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, ".")
		}
	}
	return ""
}

func (r *DNSResolver) GetTXT(domain string) []string {
	resp := r.queryAll(domain, dns.TypeTXT)
	if resp == nil {
		return nil
	}
	var txts []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			txts = append(txts, strings.Join(txt.Txt, ""))
		}
	}
	return txts
}

func (r *DNSResolver) GetCAA(domain string) []string {
	answers := r.query(domain, dns.TypeCAA)
	var caa []string
	for _, ans := range answers {
		if c, ok := ans.(*dns.CAA); ok {
			caa = append(caa, fmt.Sprintf("%s %s", c.Tag, c.Value))
		}
	}
	return caa
}

func (r *DNSResolver) AXFR(domain string) []string {
	nsList := r.GetNS(domain)
	if len(nsList) == 0 {
		return nil
	}

	if len(nsList) > 3 {
		nsList = nsList[:3]
	}

	subSet := make(map[string]struct{})

	for _, ns := range nsList {
		nsIPs := r.ResolveA(ns)
		if len(nsIPs) == 0 {
			continue
		}

		t := new(dns.Transfer)
		t.DialTimeout = 5 * time.Second
		t.ReadTimeout = 5 * time.Second

		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))

		ch, err := t.In(m, net.JoinHostPort(nsIPs[0], "53"))
		if err != nil {
			continue
		}

		done := make(chan struct{}, 1)
		go func() {
			for env := range ch {
				if env.Error != nil {
					break
				}
				for _, rr := range env.RR {
					name := strings.TrimSuffix(rr.Header().Name, ".")
					if name != domain {
						subSet[name] = struct{}{}
					}
				}
			}
			done <- struct{}{}
		}()

		select {
		case <-done:
		case <-time.After(8 * time.Second):
		}

		if len(subSet) > 0 {
			break
		}
	}

	var subs []string
	for s := range subSet {
		subs = append(subs, s)
	}
	return subs
}

func formatDuration(seconds uint32) string {
	if seconds == 0 {
		return "0 sec"
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d day%s", days, plural(days)))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hour%s", hours, plural(hours)))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d min", minutes))
	}
	if secs > 0 && days == 0 {
		parts = append(parts, fmt.Sprintf("%d sec", secs))
	}

	return strings.Join(parts, " ")
}

func plural(n uint32) string {
	if n > 1 {
		return "s"
	}
	return ""
}

func GetDomainInfo(domain string, servers []string) {
	r := NewDNSResolver(servers)

	domainIPs := r.ResolveA(domain)
	domainAAAAs := r.ResolveAAAA(domain)

	allIPs := append(domainIPs, domainAAAAs...)

	fmt.Printf("Domain\n%s", domain)
	if len(allIPs) > 0 {
		fmt.Printf(" [%s]", strings.Join(allIPs, ", "))
	}
	fmt.Println()

	if cname := r.GetCNAME(domain); cname != "" {
		fmt.Printf("\nCNAME\n%s\n", cname)
	}

	fmt.Println("\nMX records")
	for _, mx := range r.GetMX(domain) {
		fmt.Printf("%s\n", mx)
	}

	fmt.Println("\nNS records")
	for _, ns := range r.GetNS(domain) {
		nsIPs := r.ResolveA(ns)
		ipStr := strings.Join(nsIPs, ", ")
		if ipStr != "" {
			fmt.Printf("%s [%s]\n", ns, ipStr)
		} else {
			fmt.Printf("%s\n", ns)
		}
	}

	fmt.Println("\nTXT records")
	for _, txt := range r.GetTXT(domain) {
		fmt.Printf("%s\n", txt)
	}

	if soa := r.GetSOA(domain); soa != nil {
		fmt.Println("\nSOA records")
		fmt.Printf("Primary NS: %s [%s]\n", soa["primary_ns"], strings.Join(soa["primary_ns_ips"].([]string), ", "))
		fmt.Printf("Admin Email: %s\n", soa["admin_email"])
		fmt.Printf("TTL: Serial=%d, Refresh=%s, Retry=%s, Expire=%s, Min TTL=%s\n",
			soa["serial"], formatDuration(soa["refresh"].(uint32)), formatDuration(soa["retry"].(uint32)),
			formatDuration(soa["expire"].(uint32)), formatDuration(soa["ttl"].(uint32)))
	}

	fmt.Println("\nAXFR Transfer")
	subs := r.AXFR(domain)
	if len(subs) > 0 {
		for _, sub := range subs {
			ips := r.ResolveA(sub)
			ipStr := strings.Join(ips, ", ")
			if ipStr != "" {
				fmt.Printf("%s [%s]\n", sub, ipStr)
			} else {
				fmt.Printf("%s\n", sub)
			}
		}
	} else {
		fmt.Println("AXFR failed or not available")
	}
}
