package subscription

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MatcherSubstring = "substring"
	MatcherRegex     = "regex"
	OverrideAuto     = "auto"
	OverrideInclude  = "include"
	OverrideExclude  = "exclude"
)

type Matcher struct {
	ID       string
	Pattern  string
	Type     string
	Priority int
	Enabled  bool
	compiled *regexp.Regexp
}

type Classification struct {
	Node            ImportedNode
	Candidate       bool
	CandidateSource string
	MatchedMatcher  string
}

func CompileMatchers(matchers []Matcher) ([]Matcher, error) {
	result := append([]Matcher(nil), matchers...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].Priority < result[j].Priority })
	regexCount := 0
	for index := range result {
		if result[index].ID == "" || result[index].Pattern == "" || !utf8.ValidString(result[index].Pattern) || len([]byte(result[index].Pattern)) > 256 {
			return nil, fmt.Errorf("matcher %d has invalid id or pattern", index)
		}
		switch result[index].Type {
		case MatcherSubstring:
			result[index].Pattern = normalizeNodeName(result[index].Pattern)
		case MatcherRegex:
			if result[index].Enabled {
				regexCount++
				if regexCount > 32 {
					return nil, errors.New("more than 32 enabled regex matchers are not allowed")
				}
			}
			compiled, err := regexp.Compile("(?i)" + result[index].Pattern)
			if err != nil {
				return nil, fmt.Errorf("compile matcher %s: %w", result[index].ID, err)
			}
			result[index].compiled = compiled
		default:
			return nil, fmt.Errorf("matcher %s has unsupported type %q", result[index].ID, result[index].Type)
		}
	}
	return result, nil
}

func Classify(nodes []ImportedNode, matchers []Matcher, overrides map[string]string) ([]Classification, error) {
	compiled, err := CompileMatchers(matchers)
	if err != nil {
		return nil, err
	}
	result := make([]Classification, len(nodes))
	hasAutomaticMatch := false
	for index, node := range nodes {
		result[index].Node = node
		override := overrides[node.Fingerprint]
		if override == OverrideExclude {
			result[index].CandidateSource = "MANUAL_EXCLUDE"
			continue
		}
		if override == OverrideInclude {
			result[index].Candidate = true
			result[index].CandidateSource = "MANUAL_INCLUDE"
			continue
		}
		if override != "" && override != OverrideAuto {
			return nil, fmt.Errorf("node %s has invalid override %q", node.ExternalName, override)
		}
		for _, matcher := range compiled {
			if !matcher.Enabled {
				continue
			}
			matched := false
			switch matcher.Type {
			case MatcherSubstring:
				matched = strings.Contains(node.MatchName, matcher.Pattern)
			case MatcherRegex:
				matched = matcher.compiled.MatchString(node.MatchName)
			}
			if matched {
				result[index].Candidate = true
				result[index].CandidateSource = "NAME_MATCH"
				result[index].MatchedMatcher = matcher.ID
				hasAutomaticMatch = true
				break
			}
		}
	}
	if !hasAutomaticMatch {
		for index := range result {
			if result[index].CandidateSource == "MANUAL_EXCLUDE" || result[index].CandidateSource == "MANUAL_INCLUDE" {
				continue
			}
			result[index].Candidate = true
			result[index].CandidateSource = "NO_NAME_MATCH_FALLBACK_ALL"
		}
	} else {
		for index := range result {
			if result[index].CandidateSource == "" {
				result[index].CandidateSource = "NAME_FILTERED"
			}
		}
	}
	return result, nil
}

func DefaultMatchers() []Matcher {
	patterns := []string{"обход", "lte", "white list", "whitelist", "белый список", "белые списки"}
	result := make([]Matcher, len(patterns))
	for index, pattern := range patterns {
		result[index] = Matcher{ID: fmt.Sprintf("default-%d", index+1), Pattern: pattern, Type: MatcherSubstring, Priority: (index + 1) * 10, Enabled: true}
	}
	return result
}
