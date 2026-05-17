# NetrixRecon

Domain reconnaissance and asset collection tool.

## Install

```bash
go install github.com/z1un/netrixrecon@latest
```

Or build from source:

```bash
git clone https://github.com/z1un/netrixrecon.git
cd netrixrecon
go build -o netrixrecon .
```

## Usage

```
netrixrecon example.com                  # run API discovery + subdomain bruteforce
netrixrecon --whois example.com          # WHOIS lookup
netrixrecon --dns example.com            # DNS info only
netrixrecon --api example.com            # API discovery only
netrixrecon --brute example.com          # subdomain bruteforce only
netrixrecon example.com -s -o out.txt    # silent mode, export to file
netrixrecon example.com -w dict/subdomainlist.txt -t 100   # custom wordlist and threads
netrixrecon example.com -n 8.8.8.8,1.1.1.1                 # custom DNS servers (:53 auto-added)
echo example.com | netrixrecon           # pipe input
```

### Options

```
Usage: netrixrecon [flags] <domain> [options]

Actions (appear before domain, accept -- prefix):
  --whois       Lookup WHOIS information
  --dns         Run DNS information collection (A, AAAA, NS, MX, SOA, TXT, AXFR)
  --api         Run API asset discovery (FOFA, Shodan, DNSDumpster, VirusTotal, crt.sh)
  --brute       Run subdomain bruteforce

Options (appear after domain):
  -v, --version     Print version and exit
  -l, --log         Write log file to output/
  -s, --silent      Silent mode, machine-friendly output (domain/IP list only)
  -w, --wordlist <file>   Wordlist path (default: dict/subdomainlist.txt)
  -n, --ns <str>    DNS servers, comma separated (default: 8.8.8.8:53,1.1.1.1:53)
  -t, --threads <num>     Bruteforce threads (default: 200)
  -o, --output <file>     Export deduplicated assets to file
```

## API Keys (optional)

Set these environment variables to enable API-based asset discovery:

```bash
export FOFA_API_KEY="your_key"
export DNSDUMPSTER_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
```

| Variable | Source |
|----------|--------|
| `FOFA_API_KEY` | [fofa.info](https://fofa.info) |
| `DNSDUMPSTER_API_KEY` | [dnsdumpster.com](https://dnsdumpster.com) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://virustotal.com) |
| `SHODAN_API_KEY` | [shodan.io](https://shodan.io) |

FOFA search can be customized via `FOFA_QUERY` (default: ``domain="%s" || host="%s" || cert="%s"``). `%s` is replaced with the target domain.

```bash
export FOFA_QUERY='(domain="%s" || host="%s")'
```

crt.sh requires no key and is always enabled.

## License

MIT
