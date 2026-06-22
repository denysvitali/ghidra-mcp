package schema

import (
	"sort"
	"testing"
)

func TestSanitizeToolName(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		// Lowercase + collapse
		{"GetFunctionByAddress", "getfunctionbyaddress", false},
		// Replace invalid chars with single underscore
		{"foo/bar.baz qux", "foo_bar_baz_qux", false},
		// Collapse multiple underscores
		{"foo___bar", "foo_bar", false},
		// Trim leading/trailing underscores (originated by separators)
		{"/foo/bar/", "foo_bar", false},
		// Long input gets truncated to 64 chars, trailing underscores trimmed
		{repeat("a", 70), repeat("a", 64), false},
		{repeat("a", 64) + "_extra", repeat("a", 64), false},
		// Empty after sanitization
		{"////", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := SanitizeToolName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestAllocateToolName(t *testing.T) {
	used := map[string]struct{}{}
	first, err := AllocateToolName("foo", used)
	if err != nil {
		t.Fatal(err)
	}
	if first != "foo" {
		t.Fatalf("first allocation: got %q, want foo", first)
	}

	second, err := AllocateToolName("foo", used)
	if err != nil {
		t.Fatal(err)
	}
	if second != "foo_2" {
		t.Fatalf("second: got %q, want foo_2", second)
	}

	third, err := AllocateToolName("foo", used)
	if err != nil {
		t.Fatal(err)
	}
	if third != "foo_3" {
		t.Fatalf("third: got %q, want foo_3", third)
	}

	// Truncation: a name already at the limit collides with a truncated
	// version of itself.
	used2 := map[string]struct{}{}
	full := repeat("a", 64)
	got, err := AllocateToolName(full, used2)
	if err != nil {
		t.Fatal(err)
	}
	if got != full {
		t.Errorf("first: got %q (len %d)", got, len(got))
	}
	got2, err := AllocateToolName(full, used2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2) > 64 {
		t.Errorf("second exceeds 64 chars: %q (len %d)", got2, len(got2))
	}
	if got2 == full {
		t.Errorf("second should differ from full, got %q", got2)
	}
}

func TestParse_NormalizesEndpointPaths(t *testing.T) {
	raw := &RawSchema{
		Tools: []RawTool{
			{Path: "/server/status", Method: "GET", Description: "Server status",
				Category: "server", Params: []RawParam{}},
		},
	}
	tools, err := Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("got %d tools", len(tools))
	}
	if tools[0].Name != "server_status" {
		t.Errorf("name = %q, want server_status", tools[0].Name)
	}
}

func TestParse_SuffixesStaticCollisions(t *testing.T) {
	raw := &RawSchema{
		Tools: []RawTool{
			{Path: "/x/list_instances", Method: "GET", Name: "list_instances",
				Description: "dup", Params: []RawParam{}},
			{Path: "/y/list_instances", Method: "GET", Name: "list_instances_v2",
				Description: "dup", Params: []RawParam{}},
		},
	}
	tools, err := Parse(raw, []string{"list_instances"})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	sort.Strings(names)
	// First is preserved (matches static), second is suffixed.
	want := []string{"list_instances", "list_instances_v2"}
	sort.Strings(want)
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range names {
		if names[i] != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestParse_TypeNormalization(t *testing.T) {
	raw := &RawSchema{
		Tools: []RawTool{
			{Path: "/x", Method: "POST", Name: "x", Params: []RawParam{
				{Name: "a", Type: "string"},
				{Name: "b", Type: "integer"},
				{Name: "c", Type: "boolean"},
				{Name: "d", Type: "number"},
				{Name: "e", Type: "object"},
				{Name: "f", Type: "array"},
				{Name: "g", Type: ""},
				{Name: "h", Type: "weird"},
			}},
		},
	}
	tools, err := Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("got %d tools", len(tools))
	}
	wantTypes := []string{"string", "integer", "boolean", "number", "object", "array", "string", "string"}
	for i, want := range wantTypes {
		if got := tools[0].Params[i].Type; got != want {
			t.Errorf("param %d type = %q, want %q", i, got, want)
		}
	}
}

func TestParse_SourceNormalization(t *testing.T) {
	raw := &RawSchema{
		Tools: []RawTool{
			{Path: "/x", Method: "POST", Name: "x", Params: []RawParam{
				{Name: "a", Source: "body"},
				{Name: "b", Source: "QUERY"},
				{Name: "c", Source: ""},
				{Name: "d", Source: "weird"},
			}},
		},
	}
	tools, err := Parse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []ParamSource{SourceBody, SourceQuery, SourceBody, SourceBody}
	for i, w := range want {
		if got := tools[0].Params[i].Source; got != w {
			t.Errorf("param %d source = %q, want %q", i, got, w)
		}
	}
}
