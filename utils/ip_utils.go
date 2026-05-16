package utils

import "net/netip"

func IsValidIP(ip string) bool {
	_, err := netip.ParseAddr(ip)
	return err == nil
}

func ExpandIPRange(ipOrNet string) []string {
	if p, err := netip.ParsePrefix(ipOrNet); err == nil {
		var ips []string
		addr := p.Addr()
		for {
			if !p.Contains(addr) {
				break
			}
			ips = append(ips, addr.String())
			addr = addr.Next()
			if addr == p.Addr() {
				break
			}
		}
		if len(ips) == 0 {
			return []string{ipOrNet}
		}
		return ips
	}
	return []string{ipOrNet}
}

func IsIPInNetworks(ip string, networks []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range networks {
		if p, err := netip.ParsePrefix(n); err == nil {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}
