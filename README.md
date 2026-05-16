# NetrixRecon

Domain reconnaissance and asset collection tool.

## Build

```bash
go build -o netrixrecon .
```

## Usage

```bash
./netrixrecon example.com                  # run all modules
./netrixrecon -dns example.com             # DNS info only
./netrixrecon -api example.com             # API discovery only
./netrixrecon -brute example.com           # subdomain bruteforce only
./netrixrecon example.com -s -o out.txt    # silent mode, export to file
echo example.com | ./netrixrecon           # pipe input
```

Options after domain: `-l` (log), `-s` (silent), `-w <file>` (wordlist), `-n <str>` (DNS servers), `-t <num>` (threads), `-o <file>` (output).

## API Keys (optional)

| Variable | Source |
|----------|--------|
| `FOFA_API_KEY` | [fofa.info](https://fofa.info) |
| `DNSDUMPSTER_API_KEY` | [dnsdumpster.com](https://dnsdumpster.com) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://virustotal.com) |

crt.sh requires no key and is always enabled.

## License

MIT
