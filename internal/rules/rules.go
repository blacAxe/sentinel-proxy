package rules

import (
	"encoding/json"
	"os"
	"strings"
)

type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

var Rules []Rule

func LoadRules() {
	file, err := os.ReadFile("internal/rules/rules.json")
	if err != nil {
		panic(err)
	}

	json.Unmarshal(file, &Rules)
}

func IsMalicious(query string) (bool, string) {
	query = strings.ToLower(query)

	for _, rule := range Rules {
		if strings.Contains(query, rule.Pattern) {
			return true, rule.Name
		}
	}

	return false, ""
}