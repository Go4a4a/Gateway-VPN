package subscription

import "testing"

func TestClassifyUsesNamedCandidatesWhenMatchesExist(t *testing.T) {
	nodes := []ImportedNode{
		{ExternalName: "ОБХОД Москва", MatchName: normalizeNodeName("ОБХОД Москва"), Fingerprint: "one"},
		{ExternalName: "Normal", MatchName: normalizeNodeName("Normal"), Fingerprint: "two"},
		{ExternalName: "Manual", MatchName: normalizeNodeName("Manual"), Fingerprint: "three"},
	}
	result, err := Classify(nodes, DefaultMatchers(), map[string]string{"three": OverrideInclude})
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if !result[0].Candidate || result[0].CandidateSource != "NAME_MATCH" {
		t.Fatalf("matched node = %+v", result[0])
	}
	if result[1].Candidate || result[1].CandidateSource != "NAME_FILTERED" {
		t.Fatalf("normal node = %+v", result[1])
	}
	if !result[2].Candidate || result[2].CandidateSource != "MANUAL_INCLUDE" {
		t.Fatalf("manual node = %+v", result[2])
	}
}

func TestClassifyFallsBackToAllWhenNoNamesMatch(t *testing.T) {
	nodes := []ImportedNode{
		{ExternalName: "Alpha", MatchName: "alpha", Fingerprint: "one"},
		{ExternalName: "Beta", MatchName: "beta", Fingerprint: "two"},
	}
	result, err := Classify(nodes, DefaultMatchers(), nil)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	for _, item := range result {
		if !item.Candidate || item.CandidateSource != "NO_NAME_MATCH_FALLBACK_ALL" {
			t.Fatalf("fallback item = %+v", item)
		}
	}
}

func TestRegexMatcherUsesRE2AndLimits(t *testing.T) {
	matchers := []Matcher{{ID: "regex", Pattern: `^(lte|обход)[ -]`, Type: MatcherRegex, Enabled: true}}
	result, err := Classify([]ImportedNode{{ExternalName: "LTE - one", MatchName: "lte - one", Fingerprint: "one"}}, matchers, nil)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if !result[0].Candidate || result[0].CandidateSource != "NAME_MATCH" {
		t.Fatalf("regex result = %+v", result[0])
	}
	if _, err := CompileMatchers([]Matcher{{ID: "bad", Pattern: `(?=lte)`, Type: MatcherRegex, Enabled: true}}); err == nil {
		t.Fatal("CompileMatchers(lookahead) error = nil")
	}
}
