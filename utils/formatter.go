package utils

func FormatOutput(platform string, domains, ips []string, logToFile bool, domain, timestamp string) {
	logger := SetupLogger(platform, logToFile, domain, timestamp)
	defer logger.Close()

	expandedMap := make(map[string]struct{})
	for _, ip := range ips {
		for _, expanded := range ExpandIPRange(ip) {
			expandedMap[expanded] = struct{}{}
		}
	}
	var expandedIPs []string
	for ip := range expandedMap {
		expandedIPs = append(expandedIPs, ip)
	}

	for _, d := range domains {
		logger.Host(d)
	}
	logger.Info("%s total unique domains: %d", platform, len(domains))
	for _, ip := range expandedIPs {
		logger.IP(ip)
	}
	logger.Info("%s total unique IPs: %d", platform, len(expandedIPs))
}
