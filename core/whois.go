package core

import (
	"fmt"
	"strings"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func GetWhoisInfo(domain string) {
	raw, err := whois.Whois(domain)
	if err != nil {
		fmt.Printf("WHOIS lookup failed: %v\n", err)
		return
	}

	result, err := whoisparser.Parse(raw)
	if err != nil {
		fmt.Printf("WHOIS parse failed: %v\n\nRaw output:\n%s\n", err, raw)
		return
	}

	if result.Domain != nil {
		d := result.Domain
		fmt.Println("Domain")
		if d.Domain != "" {
			fmt.Printf("Domain:       %s\n", d.Domain)
		}
		if len(d.Status) > 0 {
			fmt.Printf("Status:       %s\n", strings.Join(d.Status, ", "))
		}
		if len(d.NameServers) > 0 {
			fmt.Printf("Name Servers: %s\n", strings.Join(d.NameServers, ", "))
		}
		if d.DNSSec {
			fmt.Println("DNSSEC:       yes")
		}
		if d.WhoisServer != "" {
			fmt.Printf("Whois Server: %s\n", d.WhoisServer)
		}

		fmt.Println("\nDates")
		if d.CreatedDate != "" {
			fmt.Printf("Created:    %s\n", d.CreatedDate)
		}
		if d.UpdatedDate != "" {
			fmt.Printf("Updated:    %s\n", d.UpdatedDate)
		}
		if d.ExpirationDate != "" {
			fmt.Printf("Expiration: %s\n", d.ExpirationDate)
		}
	}

	if result.Registrar != nil && result.Registrar.Name != "" {
		fmt.Println("\nRegistrar")
		printContact(result.Registrar, false)
	}

	if result.Registrant != nil && result.Registrant.Name != "" {
		fmt.Println("\nRegistrant")
		printContact(result.Registrant, true)
	}

	if result.Administrative != nil && result.Administrative.Name != "" {
		fmt.Println("\nAdministrative Contact")
		printContact(result.Administrative, true)
	}

	if result.Technical != nil && result.Technical.Name != "" {
		fmt.Println("\nTechnical Contact")
		printContact(result.Technical, true)
	}

	if result.Billing != nil && result.Billing.Name != "" {
		fmt.Println("\nBilling Contact")
		printContact(result.Billing, true)
	}
}

func printContact(c *whoisparser.Contact, showAddress bool) {
	if c.ID != "" {
		fmt.Printf("ID:       %s\n", c.ID)
	}
	if c.Name != "" {
		fmt.Printf("Name:     %s\n", c.Name)
	}
	if c.Organization != "" {
		fmt.Printf("Org:      %s\n", c.Organization)
	}
	if c.Email != "" {
		fmt.Printf("Email:    %s\n", c.Email)
	}
	if c.Phone != "" {
		s := c.Phone
		if c.PhoneExt != "" {
			s += " ext " + c.PhoneExt
		}
		fmt.Printf("Phone:    %s\n", s)
	}
	if c.Fax != "" {
		s := c.Fax
		if c.FaxExt != "" {
			s += " ext " + c.FaxExt
		}
		fmt.Printf("Fax:      %s\n", s)
	}
	if c.ReferralURL != "" {
		fmt.Printf("URL:      %s\n", c.ReferralURL)
	}
	if showAddress {
		var parts []string
		if c.Street != "" {
			parts = append(parts, c.Street)
		}
		if c.City != "" {
			parts = append(parts, c.City)
		}
		if c.Province != "" {
			parts = append(parts, c.Province)
		}
		if c.PostalCode != "" {
			parts = append(parts, c.PostalCode)
		}
		if c.Country != "" {
			parts = append(parts, c.Country)
		}
		if len(parts) > 0 {
			fmt.Printf("Address:  %s\n", strings.Join(parts, ", "))
		}
	}
}
