package aep

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The published schema and this verifier are two statements about the same
// format, and nothing has been checking that they agree. A schema that drifts
// from the parser is worse than no schema: it tells a third party their
// document is well-formed while the tool that matters rejects it.
//
// Validating it needs a JSON Schema implementation, and this repository will
// not take a dependency for one — go.sum must stay absent, which is the
// product property CI enforces. So the checker below implements exactly the
// subset of JSON Schema that schema/aep-1.schema.json actually uses.
//
// The load-bearing detail is that it REFUSES to run against a keyword it does
// not implement, rather than skipping it. A subset checker that silently
// ignores what it does not understand would report success for constraints it
// never applied — a vacuous pass, and precisely the failure this file exists to
// prevent. Adding a keyword to the schema fails this test until the checker
// learns it.

const schemaPath = "../schema/aep-1.schema.json"

var knownKeywords = map[string]bool{
	// Structural, carried but not asserted on.
	"$schema": true, "$id": true, "$defs": true,
	"title": true, "description": true,
	// Asserted.
	"$ref": true, "type": true, "const": true, "required": true,
	"properties": true, "items": true, "pattern": true, "minimum": true,
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s is not valid JSON: %v", schemaPath, err)
	}
	return s
}

// unknownKeywords walks every subschema and reports anything the checker below
// would not enforce.
func unknownKeywords(node any, path string, found *[]string) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	for k, v := range obj {
		if !knownKeywords[k] {
			*found = append(*found, fmt.Sprintf("%s.%s", path, k))
			continue
		}
		switch k {
		case "properties", "$defs":
			if m, ok := v.(map[string]any); ok {
				for name, sub := range m {
					unknownKeywords(sub, path+"."+k+"."+name, found)
				}
			}
		case "items":
			unknownKeywords(v, path+".items", found)
		}
	}
}

func TestSchema_UsesOnlyKeywordsThisCheckerEnforces(t *testing.T) {
	var found []string
	unknownKeywords(loadSchema(t), "$", &found)
	if len(found) > 0 {
		sort.Strings(found)
		t.Fatalf("schema uses keywords this checker does not enforce, so validating "+
			"against it would pass vacuously:\n  %s\nTeach the checker these "+
			"keywords or drop them from the schema.", strings.Join(found, "\n  "))
	}
}

// resolve follows a local "#/$defs/name" reference.
func resolve(root map[string]any, ref string) (map[string]any, error) {
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	defs, ok := root["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q but the schema has no $defs", ref)
	}
	sub, ok := defs[strings.TrimPrefix(ref, prefix)].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q does not resolve", ref)
	}
	return sub, nil
}

// check validates value against schema, appending human-readable failures.
func check(t *testing.T, root, schema map[string]any, value any, path string, out *[]string) {
	t.Helper()
	fail := func(format string, args ...any) {
		*out = append(*out, path+": "+fmt.Sprintf(format, args...))
	}

	if ref, ok := schema["$ref"].(string); ok {
		sub, err := resolve(root, ref)
		if err != nil {
			t.Fatal(err)
		}
		check(t, root, sub, value, path, out)
		return
	}

	if want, ok := schema["const"]; ok && !jsonEqual(want, value) {
		fail("is %v, want the constant %v", value, want)
	}

	if pat, ok := schema["pattern"].(string); ok {
		s, isStr := value.(string)
		if !isStr {
			fail("has a pattern constraint but is not a string")
		} else if !regexp.MustCompile(pat).MatchString(s) {
			fail("%q does not match %s", s, pat)
		}
	}

	if min, ok := schema["minimum"].(float64); ok {
		n, isNum := value.(float64)
		if !isNum {
			fail("has a minimum but is not a number")
		} else if n < min {
			fail("is %v, below the minimum %v", n, min)
		}
	}

	typ, hasType := schema["type"].(string)
	if hasType && !matchesType(typ, value) {
		fail("is %T, want %s", value, typ)
		return // further assertions would be noise once the type is wrong
	}

	switch typ {
	case "object":
		obj, _ := value.(map[string]any)
		for _, r := range toStrings(schema["required"]) {
			if _, present := obj[r]; !present {
				fail("is missing required member %q", r)
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for name, sub := range props {
			v, present := obj[name]
			if !present {
				continue // absence is governed by "required" alone
			}
			subSchema, _ := sub.(map[string]any)
			check(t, root, subSchema, v, path+"."+name, out)
		}
	case "array":
		items, ok := schema["items"].(map[string]any)
		if !ok {
			return
		}
		for i, v := range value.([]any) {
			check(t, root, items, v, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

func matchesType(typ string, v any) bool {
	switch typ {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == float64(int64(n))
	}
	return false
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func validateAgainstSchema(t *testing.T, doc []byte) []string {
	t.Helper()
	root := loadSchema(t)
	var value any
	if err := json.Unmarshal(doc, &value); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	var problems []string
	check(t, root, root, value, "$", &problems)
	return problems
}

// The fixtures are engine-produced, so this asserts the published schema
// against real producer bytes rather than against an idea of them.
func TestSchema_RealFixturesValidate(t *testing.T) {
	for _, name := range []string{"sample-signed.json", "sample-unsigned.json"} {
		t.Run(name, func(t *testing.T) {
			if problems := validateAgainstSchema(t, load(t, name)); len(problems) > 0 {
				t.Fatalf("engine-produced fixture fails the published schema:\n  %s",
					strings.Join(problems, "\n  "))
			}
		})
	}
}

// A checker that accepts everything would pass the test above without asserting
// anything. Each case breaks one constraint the schema states, and the schema
// must catch each one.
func TestSchema_CatchesShapeViolations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantMsg string
	}{
		{
			name:    "wrong version",
			mutate:  func(d map[string]any) { d["version"] = "aep/9" },
			wantMsg: "want the constant",
		},
		{
			name:    "unknown chain algorithm",
			mutate:  func(d map[string]any) { d["chain"].(map[string]any)["algo"] = "md5" },
			wantMsg: "want the constant",
		},
		{
			name:    "chain head is not a sha256 hex digest",
			mutate:  func(d map[string]any) { d["chain"].(map[string]any)["head"] = "nope" },
			wantMsg: "does not match",
		},
		{
			name:    "chain missing a required member",
			mutate:  func(d map[string]any) { delete(d["chain"].(map[string]any), "genesis") },
			wantMsg: `missing required member "genesis"`,
		},
		{
			name:    "top-level member missing",
			mutate:  func(d map[string]any) { delete(d, "findings") },
			wantMsg: `missing required member "findings"`,
		},
		{
			name: "finding index is negative",
			mutate: func(d map[string]any) {
				d["findings"].([]any)[0].(map[string]any)["index"] = float64(-1)
			},
			wantMsg: "below the minimum",
		},
		{
			name: "finding index is fractional",
			mutate: func(d map[string]any) {
				d["findings"].([]any)[0].(map[string]any)["index"] = 0.5
			},
			wantMsg: "want integer",
		},
		{
			name: "finding digest is not a digest",
			mutate: func(d map[string]any) {
				d["findings"].([]any)[0].(map[string]any)["digest"] = "XYZ"
			},
			wantMsg: "does not match",
		},
		{
			name: "finding missing its link",
			mutate: func(d map[string]any) {
				delete(d["findings"].([]any)[0].(map[string]any), "link")
			},
			wantMsg: `missing required member "link"`,
		},
		{
			name: "signature algorithm not the one aep/1 defines",
			mutate: func(d map[string]any) {
				d["signature"].(map[string]any)["Algo"] = "RSA_PSS_SHA_512"
			},
			wantMsg: "want the constant",
		},
		{
			name: "window missing its bounds",
			mutate: func(d map[string]any) {
				delete(d["window"].(map[string]any), "from")
			},
			wantMsg: `missing required member "from"`,
		},
		{
			name:    "policy is not an object",
			mutate:  func(d map[string]any) { d["policy"] = "20m" },
			wantMsg: "want object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(load(t, "sample-signed.json"), &doc); err != nil {
				t.Fatal(err)
			}
			tt.mutate(doc)
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}

			problems := validateAgainstSchema(t, mutated)
			if len(problems) == 0 {
				t.Fatalf("schema accepted a document with %s", tt.name)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tt.wantMsg) {
				t.Fatalf("problems = %v, want one containing %q", problems, tt.wantMsg)
			}
		})
	}
}

// The schema describes shape and the verifier enforces integrity. Stating the
// boundary in prose is not enough — this pins it, so nobody reads a passing
// schema validation as a verified package.
func TestSchema_CannotSubstituteForVerification(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(load(t, "sample-signed.json"), &doc); err != nil {
		t.Fatal(err)
	}
	// Rewrite every chain hash to a different, still well-formed digest. The
	// document keeps its shape exactly and loses its integrity entirely.
	forged := strings.Repeat("ab", 32)
	chain := doc["chain"].(map[string]any)
	chain["genesis"], chain["head"] = forged, forged
	for _, f := range doc["findings"].([]any) {
		m := f.(map[string]any)
		m["digest"], m["prev"], m["link"] = forged, forged, forged
	}
	mutated, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	if problems := validateAgainstSchema(t, mutated); len(problems) > 0 {
		t.Fatalf("expected a forged-but-well-shaped document to satisfy the schema, got:\n  %s",
			strings.Join(problems, "\n  "))
	}
	if _, err := Verify(mutated, nil); err == nil {
		t.Fatal("the verifier accepted a document whose chain does not re-derive")
	}
}
