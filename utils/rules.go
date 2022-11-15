package utils

import (
	"encoding/json"
	"io/ioutil"
)

type CheckRange struct {
	Filename  string `json:"filename"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type ReportItem struct {
	RuleID          string      `json:"long_id"`
	RuleDescription string      `json:"rule_description"`
	RuleProvider    string      `json:"rule_provider"`
	Links           []string    `json:"links"`
	Range           *CheckRange `json:"location"`
	Description     string      `json:"description"`
	RangeAnnotation string      `json:"-"`
	Severity        string      `json:"severity"`
}

func loadReportFile(f string) ([]ReportItem, error) {
	results := struct{ Results []ReportItem }{}

	file, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(file, &results)
	if err != nil {
		return nil, err
	}
	return results.Results, nil
}
