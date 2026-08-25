package webapi

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

var registeredRoutePattern = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+) (/api/v1/[^"]+)"`)
var openAPIPathParameterPattern = regexp.MustCompile(`\{([^{}]+)\}`)

type openAPIDocument struct {
	OpenAPI    string                    `yaml:"openapi"`
	Info       map[string]any            `yaml:"info"`
	Paths      map[string]map[string]any `yaml:"paths"`
	Components map[string]map[string]any `yaml:"components"`
	Security   []map[string][]string     `yaml:"security"`
}

func TestOpenAPISpecificationMatchesEveryRegisteredAPIRoute(t *testing.T) {
	specificationPath, handlerPath := openAPITestPaths(t)
	content, err := os.ReadFile(specificationPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 || len(content) > 1<<20 {
		t.Fatalf("OpenAPI size = %d", len(content))
	}
	var document openAPIDocument
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	if document.OpenAPI != "3.1.0" || document.Info["title"] != "Gateway VPN Management API" {
		t.Fatalf("OpenAPI identity = %q %+v", document.OpenAPI, document.Info)
	}
	if len(document.Security) != 1 || len(document.Security[0]["cookieAuth"]) != 0 {
		t.Fatalf("global OpenAPI security = %+v", document.Security)
	}
	var rawDocument map[string]any
	if err := yaml.Unmarshal(content, &rawDocument); err != nil {
		t.Fatalf("decode raw OpenAPI: %v", err)
	}
	validateOpenAPIReferences(t, rawDocument, rawDocument, "#")

	handlerSource, err := os.ReadFile(handlerPath)
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool)
	for _, match := range registeredRoutePattern.FindAllSubmatch(handlerSource, -1) {
		key := strings.ToUpper(string(match[1])) + " " + string(match[2])
		if registered[key] {
			t.Fatalf("duplicate registered API route %s", key)
		}
		registered[key] = true
	}
	if len(registered) < 70 {
		t.Fatalf("registered route extraction found only %d routes", len(registered))
	}

	documented := make(map[string]bool)
	operationIDs := make(map[string]string)
	for path, pathItem := range document.Paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			t.Errorf("OpenAPI path outside versioned API: %s", path)
		}
		validateOpenAPIPathParameters(t, path, pathItem, document)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			raw, exists := pathItem[method]
			if !exists {
				continue
			}
			operation, ok := raw.(map[string]any)
			if !ok {
				t.Errorf("OpenAPI operation %s %s is %T", method, path, raw)
				continue
			}
			key := strings.ToUpper(method) + " " + path
			if documented[key] {
				t.Errorf("duplicate documented API route %s", key)
			}
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
			if method != "get" && key != "POST /api/v1/auth/login" && !operationHasParameterReference(operation, "#/components/parameters/CSRF") {
				t.Errorf("%s does not document mandatory CSRF", key)
			}
			if key == "POST /api/v1/auth/login" {
				security, exists := operation["security"].([]any)
				if !exists || len(security) != 0 {
					t.Errorf("login security override = %#v", operation["security"])
				}
			}
		}
	}
	if missing, extra := setDifference(registered, documented), setDifference(documented, registered); len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("OpenAPI route drift\nmissing: %v\nextra: %v", missing, extra)
	}
	if len(operationIDs) != len(registered) {
		t.Fatalf("OpenAPI operations = %d, registered = %d", len(operationIDs), len(registered))
	}
	assertOpenAPISecurityComponents(t, document)
}

func validateOpenAPIReferences(t *testing.T, root map[string]any, value any, location string) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || !strings.HasPrefix(reference, "#/") || resolveOpenAPIReference(root, reference) == nil {
					t.Errorf("unresolved or external OpenAPI reference at %s: %#v", location, child)
				}
				continue
			}
			validateOpenAPIReferences(t, root, child, location+"/"+key)
		}
	case []any:
		for index, child := range typed {
			validateOpenAPIReferences(t, root, child, location+"/"+strconv.Itoa(index))
		}
	}
}

func resolveOpenAPIReference(root map[string]any, reference string) any {
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

func validateOpenAPIPathParameters(t *testing.T, path string, item map[string]any, document openAPIDocument) {
	t.Helper()
	matches := openAPIPathParameterPattern.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return
	}
	rawParameters, ok := item["parameters"].([]any)
	if !ok {
		t.Errorf("path %s has no path-level parameters", path)
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
			t.Errorf("path %s has invalid parameter reference %q", path, reference)
			continue
		}
		parameterName, _ := component["name"].(string)
		declared[parameterName] = true
	}
	for _, match := range matches {
		if !declared[match[1]] {
			t.Errorf("path %s does not declare {%s}", path, match[1])
		}
	}
}

func operationHasParameterReference(operation map[string]any, expected string) bool {
	parameters, _ := operation["parameters"].([]any)
	for _, raw := range parameters {
		entry, _ := raw.(map[string]any)
		if entry["$ref"] == expected {
			return true
		}
	}
	return false
}

func assertOpenAPISecurityComponents(t *testing.T, document openAPIDocument) {
	t.Helper()
	securitySchemes := document.Components["securitySchemes"]
	cookie, ok := securitySchemes["cookieAuth"].(map[string]any)
	if !ok || cookie["type"] != "apiKey" || cookie["in"] != "cookie" || cookie["name"] != sessionCookieName {
		t.Fatalf("cookieAuth schema = %#v", cookie)
	}
	parameters := document.Components["parameters"]
	csrf, ok := parameters["CSRF"].(map[string]any)
	if !ok || csrf["name"] != "X-CSRF-Token" || csrf["in"] != "header" || csrf["required"] != true {
		t.Fatalf("CSRF parameter = %#v", csrf)
	}
	schemas := document.Components["schemas"]
	errorSchema, ok := schemas["Error"].(map[string]any)
	if !ok || errorSchema["additionalProperties"] != false {
		t.Fatalf("error envelope schema = %#v", errorSchema)
	}
}

func openAPITestPaths(t *testing.T) (string, string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve OpenAPI contract test path")
	}
	directory := filepath.Dir(filename)
	return filepath.Clean(filepath.Join(directory, "..", "..", "docs", "openapi.yaml")), filepath.Join(directory, "handler.go")
}

func setDifference(left, right map[string]bool) []string {
	result := make([]string, 0)
	for key := range left {
		if !right[key] {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}
