package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/z1un/netrixrecon/api"
	"github.com/z1un/netrixrecon/core"
	"github.com/z1un/netrixrecon/utils"
)

func main() {
	const version = "20260517"

var (
		flagDNS    bool
		flagAPI    bool
		flagBrute  bool
		flagLog    bool
		flagSilent bool
		flagVersion bool
		wordlist   string
		nsFlag     string
		threads    int
		outFile    string
	)

	flag.BoolVar(&flagDNS, "dns", false, "Only run DNS information collection")
	flag.BoolVar(&flagAPI, "api", false, "Run API information collection")
	flag.BoolVar(&flagBrute, "brute", false, "Run subdomain bruteforce")
	flag.BoolVar(&flagLog, "log", false, "Write results to log file")
	flag.BoolVar(&flagSilent, "silent", false, "Only output aggregated assets without formatting")
	flag.StringVar(&wordlist, "w", "dict/subdomainlist.txt", "Subdomain wordlist path")
	flag.StringVar(&nsFlag, "ns", "8.8.8.8:53,1.1.1.1:53", "DNS servers (comma separated)")
	flag.BoolVar(&flagVersion, "v", false, "Print version and exit")
	flag.BoolVar(&flagVersion, "version", false, "Print version and exit")
	flag.IntVar(&threads, "t", 200, "Subdomain bruteforce threads")
	flag.StringVar(&outFile, "o", "", "Output deduplicated assets to file")

	flag.CommandLine.Usage = func() {
		fmt.Println(`Usage: netrixrecon [flags] <domain> [options]

Actions (appear before domain, accept -- or - prefix):
  -dns         Run DNS information collection (A, AAAA, NS, MX, SOA, TXT, AXFR)
  -api         Run API asset discovery (FOFA, DNSDumpster, VirusTotal, crt.sh)
  -brute       Run subdomain bruteforce

Options (appear after domain):
  -v, --version     Print version and exit
  -l, --log         Write log file to output/
  -s, --silent      Silent mode, machine-friendly output (domain/IP list only)
  -w, --wordlist <file>   Wordlist path (default: dict/subdomainlist.txt)
  -n, --ns <str>    DNS servers, comma separated (default: 8.8.8.8:53,1.1.1.1:53)
  -t, --threads <num>     Bruteforce threads (default: 200)
  -o, --output <file>     Export deduplicated assets to file

Examples:
  ./netrixrecon example.com
  ./netrixrecon -dns example.com
  ./netrixrecon example.com -s -o results.txt
  echo example.com | ./netrixrecon`)
	}

	flag.Parse()

	if flagVersion {
		fmt.Println("netrixrecon version", version)
		os.Exit(0)
	}

	parseFlagsFromArgs(&flagDNS, &flagAPI, &flagBrute, &flagLog, &flagSilent, &threads, &outFile, &wordlist, &nsFlag)

	servers := strings.Split(nsFlag, ",")
	for i := range servers {
		servers[i] = strings.TrimSpace(servers[i])
		if !strings.Contains(servers[i], ":") {
			servers[i] += ":53"
		}
	}

	var domains []string
	if flag.NArg() > 0 {
		d := flag.Arg(0)
		if !utils.IsValidDomain(d) {
			fmt.Fprintf(os.Stderr, "error: invalid domain: %s\n\n", d)
			flag.CommandLine.Usage()
			os.Exit(1)
		}
		domains = append(domains, d)
	}

	if len(domains) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if d := strings.TrimSpace(scanner.Text()); d != "" {
					domains = append(domains, d)
				}
			}
		}
	}

	if len(domains) == 0 {
		flag.CommandLine.Usage()
		os.Exit(1)
	}

	var allResults []resultSet

	for _, domain := range domains {
		rs := processDomain(domain, flagDNS, flagAPI, flagBrute, flagLog, flagSilent, wordlist, servers, threads)
		allResults = append(allResults, rs)
	}

	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		seen := make(map[string]struct{})
		for _, rs := range allResults {
			for _, d := range rs.domains {
				if _, ok := seen[d]; !ok {
					fmt.Fprintln(f, d)
					seen[d] = struct{}{}
				}
			}
			for _, ip := range rs.ips {
				if _, ok := seen[ip]; !ok {
					fmt.Fprintln(f, ip)
					seen[ip] = struct{}{}
				}
			}
		}
	}
}

type resultSet struct {
	domains []string
	ips     []string
}

func parseFlagsFromArgs(flagDNS, flagAPI, flagBrute, flagLog, flagSilent *bool, threads *int, outFile, wordlist, nsFlag *string) {
	args := flag.Args()
	if len(args) < 2 {
		return
	}
	remaining := args[1:]
	for i := 0; i < len(remaining); i++ {
		arg := remaining[i]
		switch arg {
		case "--dns", "-dns":
			*flagDNS = true
		case "--api", "-api":
			*flagAPI = true
		case "--brute", "-brute":
			*flagBrute = true
		case "--log", "-log", "-l":
			*flagLog = true
		case "--silent", "-silent", "-s":
			*flagSilent = true
		case "-o", "--output":
			if i+1 < len(remaining) {
				*outFile = remaining[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(remaining) {
				val, err := strconv.Atoi(remaining[i+1])
				if err == nil && val > 0 {
					*threads = val
				}
				i++
			}
		case "-w", "--wordlist":
			if i+1 < len(remaining) {
				*wordlist = remaining[i+1]
				i++
			}
		case "-n", "--ns":
			if i+1 < len(remaining) {
				*nsFlag = remaining[i+1]
				i++
			}
		}
	}
}

func processDomain(domain string, flagDNS, flagAPI, flagBrute, flagLog, flagSilent bool, wordlist string, servers []string, threads int) resultSet {
	timestamp := time.Now().Format("20060102_150405")
	ts := utils.Timestamp

	if flagDNS {
		core.GetDomainInfo(domain, servers)
		return resultSet{}
	}

	specificMode := flagAPI || flagBrute
	runAll := !specificMode

	var allIPs []string
	domainSet := make(map[string]struct{})

	if flagAPI || runAll {
		modules := api.LoadEnabledAPIs()
		for _, mod := range modules {
			if mod.API == nil {
				if !flagSilent {
					utils.WarnPrintf("[%s] [WARN] %s: skipped (%s)\n", ts(), mod.Name, mod.Reason)
				}
				continue
			}
			if !flagSilent {
				utils.InfoPrintf("[%s] [INFO] Processing %s API...\n", ts(), mod.Name)
			}
			domains, ips, err := mod.API.ExtractAssets(domain)
			if err != nil {
				if !flagSilent {
					utils.ErrorPrintf("[%s] [ERROR] %s: %v\n", ts(), mod.Name, err)
				}
				continue
			}
			for _, d := range domains {
				domainSet[d] = struct{}{}
			}
			allIPs = append(allIPs, ips...)
			if !flagSilent {
				utils.FormatOutput(mod.Name, domains, ips, flagLog, domain, timestamp)
			}
		}
	}

	if flagBrute || runAll {
		if !flagSilent {
			utils.InfoPrintf("[%s] [INFO] Processing SubDomain Bruteforce...\n", ts())
		}
		bruter := core.NewSubdomainBruter(domain, wordlist, threads, servers)
		results := bruter.Brute(flagSilent)
		var subdomains, subIPs []string
		for sub, ip := range results {
			subdomains = append(subdomains, sub)
			subIPs = append(subIPs, ip)
		}
		for _, d := range subdomains {
			domainSet[d] = struct{}{}
		}
		allIPs = append(allIPs, subIPs...)
		if !flagSilent {
			utils.FormatOutput("SUBDOMAINBRUTE", subdomains, subIPs, flagLog, domain, timestamp)
		}
	}

	rsDomains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		rsDomains = append(rsDomains, d)
	}
	ipSet := make(map[string]struct{})
	for _, ip := range allIPs {
		ipSet[ip] = struct{}{}
	}
	rsIPs := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		rsIPs = append(rsIPs, ip)
	}

	if flagSilent {
		for _, d := range rsDomains {
			fmt.Println(d)
		}
		for _, ip := range rsIPs {
			fmt.Println(ip)
		}
	} else {
		utils.FormatOutput("AGGREGATED", rsDomains, rsIPs, flagLog, domain, timestamp)
	}

	return resultSet{domains: rsDomains, ips: rsIPs}
}
