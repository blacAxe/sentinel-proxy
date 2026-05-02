package rules

import "strings"

type Rule struct {
	Name  string
	Check func(string) bool
}

// Define rules using your struct
var Rules = []Rule{
	{"SQLi - UNION", func(q string) bool {
		return strings.Contains(q, "union")
	}},
	{"SQLi - Comment", func(q string) bool {
		return strings.Contains(q, "--")
	}},
	{"SQLi - OR 1=1", func(q string) bool {
		return strings.Contains(q, "or1=1")
	}},
	{"XSS - Script Tag", func(q string) bool {
		return strings.Contains(q, "script")
	}},
	{"XSS - Event Handler", func(q string) bool {
		return strings.Contains(q, "onerror") ||
			strings.Contains(q, "onload")
	}},
}

// EXPORTED function 
func IsMalicious(query string) (bool, string) {
	query = strings.ToLower(query)

	for _, rule := range Rules {
		if rule.Check(query) {
			return true, rule.Name
		}
	}

	return false, ""
}