package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/z1un/netrixrecon/utils"
)

func randInt(max int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return n.Int64()
}

type SubdomainBruter struct {
	domain   string
	wordlist string
	threads  int
	servers  []string
}

func NewSubdomainBruter(domain, wordlist string, threads int, servers []string) *SubdomainBruter {
	if threads <= 0 {
		threads = utils.DefaultThreads
	}
	if len(servers) == 0 {
		servers = utils.DefaultNameservers
	}
	return &SubdomainBruter{
		domain:   domain,
		wordlist: wordlist,
		threads:  threads,
		servers:  servers,
	}
}

func resolveA(domain string, servers []string) []string {
	c := &dns.Client{Timeout: utils.DNSTimeout}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.SetEdns0(4096, false)

	for _, server := range servers {
		r, _, err := c.Exchange(m, server)
		if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
			continue
		}
		var ips []string
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		if len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func (b *SubdomainBruter) loadWordlist() ([]string, error) {
	data, err := os.ReadFile(b.wordlist)
	if err != nil {
		exe, err2 := os.Executable()
		if err2 == nil {
			altPath := filepath.Join(filepath.Dir(exe), b.wordlist)
			data, err = os.ReadFile(altPath)
		}
		if err != nil {
			return nil, err
		}
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var subs []string
	for _, line := range lines {
		if s := strings.TrimSpace(line); s != "" {
			subs = append(subs, s)
		}
	}
	return subs, nil
}

func (b *SubdomainBruter) checkWildcard() []string {
	var resolved []string
	cidrs := make(map[string]int)

	for i := 0; i < 5; i++ {
		randSub := fmt.Sprintf("%x%d.%s", randInt(1000000), i, b.domain)
		ips := resolveA(randSub, b.servers)
		if len(ips) > 0 {
			resolved = append(resolved, ips[0])
			parts := strings.Split(ips[0], ".")
			if len(parts) >= 2 {
				cidrs[parts[0]+"."+parts[1]]++
			}
		}
	}

	if len(resolved) == 5 && len(cidrs) == 1 {
		return resolved
	}
	return nil
}

func isWildcardMatch(ip string, wildcardIPs []string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return false
	}
	ipCIDR := parts[0] + "." + parts[1]

	for _, wip := range wildcardIPs {
		wparts := strings.Split(wip, ".")
		if len(wparts) >= 2 {
			if ipCIDR == wparts[0]+"."+wparts[1] {
				return true
			}
		}
	}
	return false
}

func (b *SubdomainBruter) Brute(silent bool) map[string]string {
	results := make(map[string]string)
	var mu sync.Mutex
	var checked atomic.Int64

	wildcardIPs := b.checkWildcard()
	isWildcard := len(wildcardIPs) > 0

	if isWildcard && !silent {
		utils.WarnPrintf("  [!] Wildcard DNS detected for %s, filtering %v\n", b.domain, wildcardIPs)
	}

	subs, err := b.loadWordlist()
	if err != nil {
		if !silent {
			utils.WarnPrintf("  [!] Failed to load wordlist: %v\n", err)
		}
		return results
	}

	total := len(subs)
	if !silent {
		utils.InfoPrintf("  [*] Loaded %d subdomains, using %d threads\n", total, b.threads)
	}

	start := time.Now()
	jobs := make(chan string, b.threads)
	var wg sync.WaitGroup

	var lastReported atomic.Int64
	progressDone := make(chan struct{})
	if !silent && total > 0 {
		go func() {
			for {
				c := checked.Load()
				if c >= int64(total) {
					if c > 0 {
						mu.Lock()
						n := len(results)
						mu.Unlock()
						utils.InfoPrintf("\r  [*] Progress: %5d/%-5d - Found %d subs\n", c, total, n)
					}
					close(progressDone)
					return
				}
				lr := lastReported.Load()
				if c > 0 && c-lr >= 50 {
					lastReported.Store(c)
					mu.Lock()
					n := len(results)
					mu.Unlock()
					utils.InfoPrintf("\r  [*] Progress: %5d/%-5d - Found %d subs", c, total, n)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	} else {
		close(progressDone)
	}

	for i := 0; i < b.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				fullDomain := sub + "." + b.domain
				ips := resolveA(fullDomain, b.servers)
				if len(ips) > 0 {
					ip := ips[0]
					if isWildcard && isWildcardMatch(ip, wildcardIPs) {
						checked.Add(1)
						continue
					}
					mu.Lock()
					results[fullDomain] = ip
					mu.Unlock()
				}
				checked.Add(1)
			}
		}()
	}

	for _, sub := range subs {
		jobs <- sub
	}
	close(jobs)
	wg.Wait()

	<-progressDone

	elapsed := time.Since(start)
	if !silent {
		utils.InfoPrintf("  [*] Found %d subdomains in %s\n", len(results), elapsed)
	}
	return results
}
