package vpswebapi

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var vpsRegisteredRoutePattern = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+) (/api/v1/[^\"]+)"`)
var vpsOpenAPIPathParameterPattern = regexp.MustCompile(`\{([^{}]+)\}`)

type vpsOpenAPIDocument struct {
	OpenAPI    string                    `yaml:"openapi"`
	Info       map[string]any            `yaml:"info"`
	Paths      map[string]map[string]any `yaml:"paths"`
	Components map[string]map[string]any `yaml:"components"`
	Security   []map[string][]string     `yaml:"security"`
}

func TestVPSOpenAPISpecificationMatchesEveryRegisteredAPIRoute(t *testing.T) {
	specificationPath, handlerPath := vpsOpenAPITestPaths(t)
	content, err := os.ReadFile(specificationPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 || len(content) > 1<<20 {
		t.Fatalf("VPS OpenAPI size = %d", len(content))
	}
	var document vpsOpenAPIDocument
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode VPS OpenAPI: %v", err)
	}
	if document.OpenAPI != "3.1.0" || document.Info["title"] != "Gateway VPN VPS Hub API" {
		t.Fatalf("VPS OpenAPI identity = %q %+v", document.OpenAPI, document.Info)
	}
	if len(document.Security) != 1 || len(document.Security[0]["cookieAuth"]) != 0 {
		t.Fatalf("global VPS OpenAPI security = %+v", document.Security)
	}
	var rawDocument map[string]any
	if err := yaml.Unmarshal(content, &rawDocument); err != nil {
		t.Fatalf("decode raw VPS OpenAPI: %v", err)
	}
	validateVPSOpenAPIReferences(t, rawDocument, rawDocument, "#")

	handlerSource, err := os.ReadFile(handlerPath)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool)
	for _, match := range vpsRegisteredRoutePattern.FindAllSubmatch(handlerSource, -1) {
		key := strings.ToUpper(string(match[1])) + " " + string(match[2])
		if registered[key] {
			t.Fatalf("duplicate registered VPS API route %s", key)
		}
		registered[key] = true
	}
	if len(registered) < 30 {
		t.Fatalf("registered VPS route extraction found only %d routes", len(registered))
	}

	publicMutations := map[string]bool{
		"POST /api/v1/auth/login":       true,
		"POST /api/v1/pairing/complete": true,
	}
	documented := make(map[string]bool)
	operationIDs := make(map[string]string)
	for path, pathItem := range document.Paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			t.Errorf("VPS OpenAPI path outside versioned API: %s", path)
		}
		validateVPSOpenAPIPathParameters(t, path, pathItem, document)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			raw, exists := pathItem[method]
			if !exists {
				continue
			}
			operation, ok := raw.(map[string]any)
			if !ok {
				t.Errorf("VPS OpenAPI operation %s %s is %T", method, path, raw)
				continue
			}
			key := strings.ToUpper(method) + " " + path
			documented[key] = true
			operationID, _ := operation["operationId"].(string)
			if operationID == "" {
				t.Errorf("%s has no operationId", key)
			} else if previous := operationIDs[operationID]; previous != "" {
				t.Errorf("operationId %q reused by %s and %s", operationID, previous, key)
			} else {
				operationIDs[operationID] = key
			}
			responses, ok := operation["responses"].(map[string]any)
			if !ok || len(responses) == 0 {
				t.Errorf("%s has no responses", key)
			}
			if method != "get" && !publicMutations[key] && !vpsOperationHasParameterReference(operation, "#/components/parameters/CSRF") {
				t.Errorf("%s does not document mandatory CSRF", key)
			}
			if publicMutations[key] {
				security, exists := operation["security"].([]any)
				if !exists || len(security) != 0 {
					t.Errorf("public operation %s security override = %#v", key, operation["security"])
				}
			}
		}
	}
	if missing, extra := vpsSetDifference(registered, documented), vpsSetDifference(documented, registered); len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("VPS OpenAPI route drift\nmissing: %v\nextra: %v", missing, extra)
	}
	if len(operationIDs) != len(registered) {
		t.Fatalf("VPS OpenAPI operations = %d, registered = %d", len(operationIDs), len(registered))
	}
	assertVPSOpenAPISecurityAndRelayComponents(t, document, content)
}

func validateVPSOpenAPIReferences(t *testing.T, root map[string]any, value any, location string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || !strings.HasPrefix(reference, "#/") || resolveVPSOpenAPIReference(root, reference) == nil {
					t.Errorf("unresolved or external VPS OpenAPI reference at %s: %#v", location, child)
				}
				continue
			}
			validateVPSOpenAPIReferences(t, root, child, location+"/"+key)
		}
	case []any:
		for index, child := range typed {
			validateVPSOpenAPIReferences(t, root, child, location+"/"+strconv.Itoa(index))
		}
	}
}

func resolveVPSOpenAPIReference(root map[string]any, reference string) any {
	var current any = root
	for _, raw := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[segment]
		if !ok {
			return nil
		}
	}
	return current
}

func validateVPSOpenAPIPathParameters(t *testing.T, path string, item map[string]any, document vpsOpenAPIDocument) {
	t.Helper()
	matches := vpsOpenAPIPathParameterPattern.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return
	}
	rawParameters, ok := item["parameters"].([]any)
	if !ok {
		t.Errorf("VPS path %s has no path-level parameters", path)
		return
	}
	declared := make(map[string]bool)
	for _, raw := range rawParameters {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		reference, _ := entry["$ref"].(string)
		name := strings.TrimPrefix(reference, "#/components/parameters/")
		component, exists := document.Components["parameters"][name].(map[string]any)
		if !exists || component["in"] != "path" || component["required"] != true {
			t.Errorf("VPS path %s has invalid parameter reference %q", path, reference)
			continue
		}
		parameterName, _ := component["name"].(string)
		declared[parameterName] = true
	}
	for _, match := range matches {
		if !declared[match[1]] {
			t.Errorf("VPS path %s does not declare {%s}", path, match[1])
		}
	}
}

func vpsOperationHasParameterReference(operation map[string]any, expected string) bool {
	parameters, _ := operation["parameters"].([]any)
	for _, raw := range parameters {
		entry, _ := raw.(map[string]any)
		if entry["$ref"] == expected {
			return true
		}
	}
	return false
}

func assertVPSOpenAPISecurityAndRelayComponents(t *testing.T, document vpsOpenAPIDocument, content []byte) {
	t.Helper()
	securitySchemes := document.Components["securitySchemes"]
	cookie, ok := securitySchemes["cookieAuth"].(map[string]any)
	if !ok || cookie["type"] != "apiKey" || cookie["in"] != "cookie" || cookie["name"] != sessionCookieName {
		t.Fatalf("VPS cookieAuth schema = %#v", cookie)
	}
	parameters := document.Components["parameters"]
	csrf, ok := parameters["CSRF"].(map[string]any)
	if !ok || csrf["name"] != "X-CSRF-Token" || csrf["in"] != "header" || csrf["required"] != true {
		t.Fatalf("VPS CSRF parameter = %#v", csrf)
	}
	schemas := document.Components["schemas"]
	errorSchema, ok := schemas["Error"].(map[string]any)
	if !ok || errorSchema["additionalProperties"] != false {
		t.Fatalf("VPS error envelope schema = %#v", errorSchema)
	}
	relayList, ok := schemas["AdminRelayList"].(map[string]any)
	properties, _ := relayList["properties"].(map[string]any)
	privateKeys, _ := properties["private_keys_on_vps"].(map[string]any)
	destination, _ := properties["destination_port"].(map[string]any)
	if !ok || privateKeys["const"] != false || destination["const"] != 51822 {
		t.Fatalf("VPS relay invariant schema = %#v", relayList)
	}
	if bytes.Contains(content, []byte("private_key:")) || bytes.Contains(content, []byte("private_key_secret_ref")) {
		t.Fatal("VPS OpenAPI relay contract exposes a private key field")
	}
}

func vpsOpenAPITestPaths(t *testing.T) (string, string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve VPS OpenAPI contract test path")
	}
	directory := filepath.Dir(filename)
	return filepath.Clean(filepath.Join(directory, "..", "..", "docs", "vps-openapi.yaml")), filepath.Join(directory, "handler.go")
}

func vpsSetDifference(left, right map[string]bool) []string {
	result := make([]string, 0)
	for key := range left {
		if !right[key] {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}
