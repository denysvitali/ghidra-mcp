package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
)

// Parse converts the raw /mcp/schema payload into a normalized []ToolDef
// with CAPI-safe names. Mirrors Python _parse_schema at lines 882-927.
//
// used must be seeded with the static tool names before calling. The
// function mutates used, marking every name it allocates as taken.
func Parse(raw *RawSchema, staticNames []string) ([]ToolDef, error) {
	if raw == nil {
		return nil, fmt.Errorf("nil schema")
	}

	used := make(map[string]struct{}, len(staticNames))
	for _, n := range staticNames {
		used[n] = struct{}{}
	}

	out := make([]ToolDef, 0, len(raw.Tools))
	for _, t := range raw.Tools {
		td, err := parseOne(t, used)
		if err != nil {
			// Skip the offending tool; mirror Python's per-tool error tolerance.
			continue
		}
		out = append(out, td)
	}
	return out, nil
}

func parseOne(t RawTool, used map[string]struct{}) (ToolDef, error) {
	original := t.Name
	if original == "" {
		// Derive from path: "/decompile_function" -> "decompile_function"
		original = strings.TrimPrefix(t.Path, "/")
		original = strings.ReplaceAll(original, "/", "_")
	}
	if original == "" {
		return ToolDef{}, fmt.Errorf("tool missing both name and path")
	}

	sanitized, err := SanitizeToolName(original)
	if err != nil {
		return ToolDef{}, err
	}

	// Static-name preservation: if the sanitized name collides with a static
	// tool AND the raw input is byte-identical to the static name, we keep
	// the static name (the dynamic registration layer will skip it as a
	// duplicate). Otherwise we allocate a suffixed name.
	nameCollided := false
	final := sanitized
	if _, staticUsed := used[sanitized]; staticUsed {
		if isStaticMatch(sanitized, original) {
			// Reserve the static name for the bridge's static tool.
			nameCollided = false
			final = sanitized
		} else {
			allocated, allocErr := AllocateToolName(sanitized, used)
			if allocErr != nil {
				return ToolDef{}, allocErr
			}
			final = allocated
			nameCollided = true
		}
	} else {
		used[sanitized] = struct{}{}
	}

	td := ToolDef{
		Name:          final,
		OriginalName:  original,
		SanitizedName: sanitized,
		NameCollided:  nameCollided,
		Endpoint:      t.Path,
		HTTPMethod:    strings.ToUpper(strings.TrimSpace(t.Method)),
		Description:   t.Description,
		Category:      t.Category,
		CategoryDesc:  t.CategoryDesc,
		Params:        make([]ParamDef, 0, len(t.Params)),
	}
	if td.HTTPMethod == "" {
		td.HTTPMethod = "GET"
	}
	for _, p := range t.Params {
		td.Params = append(td.Params, ParamDef{
			Name:        p.Name,
			Type:        normalizeType(p.Type),
			Description: p.Description,
			Source:      normalizeSource(p.Source),
			ParamType:   p.ParamType,
			Required:    p.Required,
			Default:     p.Default,
			Enum:        p.Enum,
		})
	}
	return td, nil
}

func isStaticMatch(staticName, rawOriginal string) bool {
	return staticName == rawOriginal
}

// normalizeType maps upstream type strings to the canonical Python-side
// _TYPE_MAP (lines 839-848). Anything unknown falls back to "string".
func normalizeType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "string", "json", "address", "any":
		return "string"
	case "integer", "int":
		return "integer"
	case "boolean", "bool":
		return "boolean"
	case "number", "float":
		return "number"
	case "object":
		return "object"
	case "array":
		return "array"
	default:
		return "string"
	}
}

func normalizeSource(s string) ParamSource {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "query":
		return SourceQuery
	case "path":
		return SourcePath
	case "", "body":
		return SourceBody
	default:
		return SourceBody
	}
}

// ParseJSON is a thin wrapper around Parse that decodes raw bytes.
func ParseJSON(data []byte, staticNames []string) ([]ToolDef, error) {
	var raw RawSchema
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode schema: %w", err)
	}
	return Parse(&raw, staticNames)
}

// Compile-time guard against unused-import errors if config becomes unused.
var _ = config.MaxToolNameLength
